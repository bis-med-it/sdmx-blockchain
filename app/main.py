import logging
import os
import json
from io import BytesIO
import lxml.etree as etree
import requests
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Response
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from fastapi import Form
import time

from app.xrpl_client import (

    get_devnet_wallet_async,
    wallet_from_seed,
    anchor_hash,
    fetch_transaction,
    get_account_balance_xrp,
)
from app.utils import compute_sha3_512_c14n, ensure_single_placeholder, message_namespace
from app.utils import compute_series_hash, merkle_root_from_hex_hashes, compute_sha3_512_raw
from app.vc import issue_vc, verify_vc, encode_vc_for_source, decode_vc_from_source_text
from app.account_store import save_wallet, load_wallet
from app.schemas import (
    WalletResponse,
    WalletLoginRequest,
    PublishRequest,
    PublishResponse,
    ErrorResponse,
    ValidateResponse,
)
from app.settings import settings

logger = logging.getLogger(__name__)
app = FastAPI(title="XRPL SDMX Publisher and Validator")

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", settings.keycloak_url or "http://keycloak:8080").rstrip("/")
REALM = os.getenv("KEYCLOAK_REALM", settings.keycloak_realm or "sdmx").strip()
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", settings.keycloak_client_id or "sdmx-client").strip()
CLIENT_SECRET = settings.keycloak_client_secret
ALGORITHMS = ["RS256"]

if not KEYCLOAK_URL or not REALM or not CLIENT_ID:
    logger.warning(
        "KEYCLOAK_URL / KEYCLOAK_REALM / KEYCLOAK_CLIENT_ID not fully configured; "
        "token validation will fail until set."
    )

def _keycloak_jwks_url() -> str:
    return f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"


def _keycloak_token_url() -> str:
    return f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"


def get_jwks():
    url = _keycloak_jwks_url()
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json()


try:
    JWKS = get_jwks()
except Exception as e:
    JWKS = None
    logger.info("JWKS not fetched at startup (Keycloak may not be ready): %s", e)

# OAuth2 scheme used by dependency injection and for OpenAPI "Authorize" button.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


def decode_token(token: str = Depends(oauth2_scheme)):
    if JWKS is None:
        raise HTTPException(
            status_code=500,
            detail="JWKS not available for token validation. Ensure Keycloak is reachable and KEYCLOAK_URL/REALM are correct.",
        )
    try:
        claims = jwt.decode(token, JWKS, algorithms=ALGORITHMS, audience=CLIENT_ID)
        return claims
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")


def require_role(role: str):
    def checker(claims=Depends(decode_token)):
        roles = claims.get("realm_access", {}).get("roles", [])
        if role not in roles:
            raise HTTPException(status_code=403, detail="Missing required role")
        return claims

    return checker


@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/token")
def token(
    username: str = Form(...),
    password: str = Form(...),
    client_id_in: str | None = Form(None),
    client_secret_in: str | None = Form(None),
):
    """
    Token proxy. Accepts optional client_id/client_secret in the form.
    If not provided, falls back to environment CLIENT_ID / CLIENT_SECRET.
    WARNING: exposing client_secret in Swagger is insecure for production.
    """
    token_url = _keycloak_token_url()

    client_id_to_use = client_id_in or CLIENT_ID
    client_secret_to_use = client_secret_in or CLIENT_SECRET

    payload = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": client_id_to_use,
    }
    if client_secret_to_use:
        payload["client_secret"] = client_secret_to_use

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        resp = requests.post(token_url, data=payload, headers=headers, timeout=10)
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Error contacting Keycloak token endpoint: {e}")

    if resp.status_code != 200:
        try:
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            return Response(content=resp.text, status_code=resp.status_code, media_type="text/plain")

    try:
        return resp.json()
    except Exception:
        return Response(content=resp.text, media_type="text/plain")

@app.post(
    "/createWallet",
    response_model=WalletResponse,
    responses={400: {"model": ErrorResponse}},
    dependencies=[Depends(require_role("wallet_admin"))],
)
async def create_wallet():
    try:
        wallet = await get_devnet_wallet_async()
        save_wallet(wallet.address, str(wallet.seed), wallet.public_key, wallet.private_key)
        balanceXrp = await get_account_balance_xrp(wallet.address)
        return WalletResponse(
            address=wallet.address, 
            seed=str(wallet.seed), 
            public_key=wallet.public_key, 
            balance_xrp=balanceXrp,
            warning="Wallet seed is held in memory only and will not survive a container restart."
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))




@app.get("/listWallets")
async def list_wallets():
    path = settings.wallet_store_path
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return []
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading wallet store: {e}")

    wallets = []
    if isinstance(data, list):
        for item in data:
            addr = item.get("address")
            if not addr:
                continue
            wallets.append({"address": addr, "public_key": item.get("public_key", "")})
    elif isinstance(data, dict):
        for addr, rec in data.items():
            wallets.append({"address": addr, "public_key": rec.get("public_key", "")})
    else:
        raise HTTPException(status_code=500, detail="Unexpected wallets.json format")

    return wallets


@app.post("/walletInfo", response_model=WalletResponse, responses={400: {"model": ErrorResponse}})
async def wallet_info(req: WalletLoginRequest):
    record = load_wallet(req.address)
    if not record:
        raise HTTPException(status_code=404, detail="Wallet not found")
    wallet = wallet_from_seed(record["seed"])
    balanceXrp = await get_account_balance_xrp(wallet.address)
    return WalletResponse(address=req.address, seed=record["seed"], public_key=record["public_key"], balance_xrp=balanceXrp)


@app.post("/clearWallets", dependencies=[Depends(require_role("wallet_admin"))])
async def clear_wallets():
    path = settings.wallet_store_path
    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)
        os.replace(tmp_path, path)
        return {"status": "cleared"}
    except Exception as e:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"Error clearing wallet store: {e}")


@app.post(
    "/publishSDMX",
    response_model=PublishResponse,
    responses={400: {"model": ErrorResponse}},
)
async def publish_sdmx(file: UploadFile = File(...), req: PublishRequest = Depends(), series: str | None = None):
    start_time = time.perf_counter()
    try:
        raw = await file.read()
        parser = etree.XMLParser(remove_blank_text=True, ns_clean=True, recover=False)
        try:
            root = etree.fromstring(raw, parser=parser)
        except etree.XMLSyntaxError:
            raise HTTPException(status_code=400, detail="Uploaded file is not valid XML.")
        
        file_read = time.perf_counter() - start_time
        print(f"Processing time for reading file is: {file_read}");


        ns_uri = message_namespace(root)
        placeholder = ensure_single_placeholder(root, ns_uri)

        # Compute per-Series hashes
        series_elements = root.findall('.//Series')
        series_hashes = []
        for s in series_elements:
            h = compute_series_hash(s)
            # try to read an identifying key from attributes (compose a short id)
            series_id = s.get('REF_AREA') or s.get('ID') or s.get('TITLE') or ''
            series_hashes.append({'id': series_id, 'hash': h})

        requested = None  # Ensure requested is always defined
        # If caller provided a comma-separated list of hex hashes to anchor, build a Merkle root
        if series:
            requested = [x.strip().upper() for x in series.split(',') if x.strip()]
            # validate requested hashes exist
            available = {item['hash'].upper() for item in series_hashes}
            missing = [r for r in requested if r not in available]
            if missing:
                raise HTTPException(status_code=400, detail=f"Requested series hashes not found: {missing}")
            merkle_root = merkle_root_from_hex_hashes(requested)
            dataset_hash = merkle_root
            # write an explicit Source indicating merkle root and count
            placeholder.text = f"Transaction Hash:{''}"  # placeholder text until tx
        else:
            xml_bytes = etree.tostring(root, encoding="utf-8", xml_declaration=True, pretty_print=False)
            dataset_hash = compute_sha3_512_c14n(xml_bytes)

        sha_time = time.perf_counter() - file_read
        print(f"Processing time for computing SHA: {sha_time}");

        record = load_wallet(req.address)
        if not record:
            raise HTTPException(status_code=404, detail="Source wallet not found")
        from app.xrpl_client import wallet_from_seed  # local import to avoid cycles

        wallet = wallet_from_seed(record["seed"])

        wallet_time = time.perf_counter() - sha_time
        print(f"Processing time for checking wallets is: {wallet_time}");

        tx_hash = await anchor_hash(wallet, dataset_hash, req.destination)
        # If series selection was used, embed a short structured Source value
        if series and requested is not None:
            placeholder.text = f"Transaction Hash:{tx_hash};Type:MerkleRoot;Root:{dataset_hash};Leaves:{len(requested)}"
            # Add an additional <message:Source> containing the ordered leaf hashes so validators can re-compute the root
            try:
                header = root.find(f".//{{{ns_uri}}}Header")
                if header is not None:
                    leaves_text = ",".join(requested)
                    etree.SubElement(header, f"{{{ns_uri}}}Source").text = f"MerkleLeaves:{leaves_text}"
            except Exception:
                # non-fatal: continue without writing leaves
                pass
        else:
            placeholder.text = f"Transaction Hash:{tx_hash}"

        # Issue and embed a W3C Verifiable Credential binding publisher identity to the anchor.
        try:
            vc = issue_vc(
                issuer_address=wallet.address,
                issuer_public_key_hex=wallet.public_key,
                issuer_private_key_hex=wallet.private_key,
                tx_hash=tx_hash,
                dataset_hash=dataset_hash,
                anchor_type="MerkleRoot" if (series and requested is not None) else "WholeFile",
                leaves=requested if (series and requested is not None) else None,
            )
            header = root.find(f".//{{{ns_uri}}}Header")
            if header is not None:
                etree.SubElement(header, f"{{{ns_uri}}}Source").text = encode_vc_for_source(vc)
        except Exception as e:
            logger.warning("VC issuance failed (non-fatal): %s", e)
        out_bytes = etree.tostring(root, encoding="utf-8", xml_declaration=True, pretty_print=False)

        processing_time = time.perf_counter() - wallet_time
        print(f"Processing time for this publication is: {processing_time}");
        return StreamingResponse(BytesIO(out_bytes), media_type="application/xml", headers={"X-Transaction-Hash": tx_hash})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/validateSDMX", response_model=ValidateResponse, responses={400: {"model": ErrorResponse}})
async def validate_sdmx(file: UploadFile = File(...)):
    start_time = time.perf_counter()
    raw = await file.read()
    parser = etree.XMLParser(remove_blank_text=True, ns_clean=True, recover=False)
    try:
        root = etree.fromstring(raw, parser=parser)
    except etree.XMLSyntaxError:
        raise HTTPException(status_code=400, detail="Uploaded file is not valid XML.")

    message_ns = message_namespace(root)
    header = root.find(f".//{{{message_ns}}}Header")
    if header is None:
        raise HTTPException(status_code=400, detail="<message:Header> not found in XML.")

    # Locate optional embedded VC; verified after we have the on-chain tx for cross-checks.
    embedded_vc: dict | None = None
    for tag_vc in header.findall(f".//{{{message_ns}}}Source"):
        decoded = decode_vc_from_source_text((tag_vc.text or "").strip())
        if decoded is not None:
            embedded_vc = decoded
            break

    tx_source_tags = []
    for tag in header.findall(f".//{{{message_ns}}}Source"):
        text = (tag.text or "").strip()
        if text.lower().startswith("transaction hash:"):
            value = text[len("Transaction Hash:"):].strip()
            tx_source_tags.append((tag, value))

    if len(tx_source_tags) > 1:
        return ValidateResponse(valid=False, reason="Multiple Transaction Hash tags found in file.")
    if len(tx_source_tags) == 0:
        return ValidateResponse(valid=False, reason="No Transaction Hash tag found in file.")

    # Take the first Transaction Hash tag and parse possible metadata (e.g. Type:MerkleRoot;Root:...;Leaves:N)
    tag, value = tx_source_tags[0]
    if not value:
        return ValidateResponse(valid=False, reason="Transaction Hash tag is empty (no transaction hash present).")

    # value may contain metadata after semicolons; tx_hash is the first token before any ';'
    parts = [p.strip() for p in value.split(";") if p.strip()]
    tx_hash_from_file = parts[0]
    meta = {}
    for token in parts[1:]:
        if ":" in token:
            k, v = token.split(":", 1)
            meta[k.strip()] = v.strip()

    # Fetch transaction from chain using tx hash only
    try:
        tx_data = await fetch_transaction(tx_hash_from_file)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error fetching transaction {tx_hash_from_file}: {e}")

    memos = tx_data.get("Memos") or tx_data.get("meta", {}).get("Memos") or []
    if not memos:
        return ValidateResponse(valid=False, reason="No memos found in the referenced transaction.")

    memo_obj = memos[0].get("Memo", {}) if isinstance(memos[0], dict) else {}
    memo_data = memo_obj.get("MemoData") or memo_obj.get("memo_data") or ""
    if not memo_data:
        return ValidateResponse(valid=False, reason="MemoData not found in transaction.")

    memo_hash = memo_data.strip().upper()

    # Verify embedded VC (if any) and cross-check publisher identity against the on-chain signer.
    vc_kwargs: dict = {}
    if embedded_vc is not None:
        sig_ok, vc_reason = verify_vc(embedded_vc)
        subject = embedded_vc.get("credentialSubject", {}) if isinstance(embedded_vc, dict) else {}
        issuer = embedded_vc.get("issuer") if isinstance(embedded_vc, dict) else None
        vc_pub = embedded_vc.get("proof", {}).get("publicKeyHex") if isinstance(embedded_vc, dict) else None
        on_chain_pub = tx_data.get("SigningPubKey")
        on_chain_account = tx_data.get("Account")
        identity_ok = bool(vc_pub) and bool(on_chain_pub) and vc_pub.upper() == on_chain_pub.upper()
        subject_tx_ok = subject.get("txHash", "").lower() == tx_hash_from_file.lower()
        subject_root_ok = subject.get("datasetHash", "").upper() == memo_hash
        vc_verified = bool(sig_ok and identity_ok and subject_tx_ok and subject_root_ok)
        reasons = [vc_reason]
        if not identity_ok:
            reasons.append(f"VC publicKeyHex does not match on-chain SigningPubKey ({on_chain_account}).")
        if not subject_tx_ok:
            reasons.append("VC subject txHash does not match referenced transaction.")
        if not subject_root_ok:
            reasons.append("VC subject datasetHash does not match on-chain memo.")
        vc_kwargs = {
            "vc_verified": vc_verified,
            "vc_issuer": issuer,
            "vc_subject": subject if isinstance(subject, dict) else None,
            "vc_reason": "; ".join(r for r in reasons if r),
        }

    # If metadata indicates this is a Merkle root anchoring, verify using MerkleLeaves found in Header
    if meta.get("Type") == "MerkleRoot" or "Root" in meta:
        # Find MerkleLeaves source in header
        leaves_tag = None
        for tag2 in header.findall(f".//{{{message_ns}}}Source"):
            t2 = (tag2.text or "").strip()
            if t2.startswith("MerkleLeaves:"):
                leaves_tag = tag2
                break

        if leaves_tag is None:
            # Attempt fallback: if the Transaction Hash metadata included a Leaves count and that count
            # equals the number of Series elements in the file, reconstruct leaves from all Series
            leaves = None
            if "Leaves" in meta:
                try:
                    leaves_count = int(meta["Leaves"]) if meta["Leaves"] is not None else None
                except Exception:
                    leaves_count = None

                if leaves_count is not None:
                    series_elements = root.findall('.//Series')
                    if leaves_count == len(series_elements) and len(series_elements) > 0:
                        leaves = [compute_series_hash(s).upper() for s in series_elements]

            if leaves is None:
                # If the anchor was for a single leaf (Leaves==1) we can try to find which series
                # produced the root by constructing the leaf node from each series hash and comparing.
                try:
                    if "Leaves" in meta and int(meta.get("Leaves", 0)) == 1:
                        series_elements = root.findall('.//Series')
                        found = False
                        for s in series_elements:
                            h = compute_series_hash(s).upper()
                            h_bytes = bytes.fromhex(h)
                            leaf = compute_sha3_512_raw(b"\x00" + len(h_bytes).to_bytes(4, byteorder="big") + h_bytes)
                            if leaf.hex().upper() == memo_hash:
                                found = True
                                break
                        if found:
                            processing_time = time.perf_counter() - start_time
                            print(f"Processing time for this validation is: {processing_time}");
                            return ValidateResponse(valid=True, reason="Transaction memo matches Merkle root for a single series present in file (valid).", **vc_kwargs)
                except Exception:
                    pass

                return ValidateResponse(valid=False, reason="Merkle-root anchor found but no MerkleLeaves present in file to validate inclusion.")
        else:
            leaves_raw = leaves_tag.text.strip()[len("MerkleLeaves:"):].strip()
            leaves = [h.strip().upper() for h in leaves_raw.split(",") if h.strip()]
            if not leaves:
                return ValidateResponse(valid=False, reason="MerkleLeaves is empty in file.")

        # Ensure leaves are present in the uploaded file's series
        parser = etree.XMLParser(remove_blank_text=True, ns_clean=True, recover=False)
        try:
            # we already have root; compute per-series hashes
            series_elements = root.findall('.//Series')
            available = {compute_series_hash(s).upper() for s in series_elements}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error computing series hashes for validation: {e}")

        missing = [h for h in leaves if h not in available]
        if missing:
            return ValidateResponse(valid=False, reason=f"Some MerkleLeaves are not present in the uploaded file: {missing}")

        # Recompute Merkle root from supplied leaves (order matters)
        try:
            recomputed_root = merkle_root_from_hex_hashes(leaves)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error computing Merkle root: {e}")

        if recomputed_root == memo_hash:
            processing_time = time.perf_counter() - start_time
            print(f"Processing time for this validation is: {processing_time}");
            return ValidateResponse(valid=True, reason="Transaction memo matches Merkle root computed from file MerkleLeaves (valid).", **vc_kwargs)
        else:
            processing_time = time.perf_counter() - start_time
            print(f"Processing time for this validation is: {processing_time}");
            return ValidateResponse(valid=False, reason=f"Memo mismatch: on-chain memo {memo_hash} != recomputed Merkle root {recomputed_root}")

    # Fallback: legacy whole-file anchoring
    tag.text = "Transaction Hash:"
    xml_bytes = etree.tostring(root, encoding="utf-8", xml_declaration=True, pretty_print=False)

    try:
        dataset_hash = compute_sha3_512_c14n(xml_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error canonicalizing/hashing XML: {e}")

    if memo_hash == dataset_hash:
        processing_time = time.perf_counter() - start_time
        print(f"Processing time for this validation is: {processing_time}");
        return ValidateResponse(valid=True, reason="Transaction memo matches dataset hash (valid).", **vc_kwargs)
    else:
        processing_time = time.perf_counter() - start_time
        print(f"Processing time for this validation is: {processing_time}");
        return ValidateResponse(
            valid=False,
            reason=f"Memo mismatch: on-chain memo {memo_hash} != computed dataset hash {dataset_hash}"
        )


@app.post("/listSeries")
async def list_series(file: UploadFile = File(...)):
    """Return a list of Series elements and their computed SHA3-512 hashes.
    The client can use the returned hashes to select which series to include in an anchor.
    """
    logger.info("/listSeries called")
    raw = await file.read()
    parser = etree.XMLParser(remove_blank_text=True, ns_clean=True, recover=False)
    try:
        root = etree.fromstring(raw, parser=parser)
    except etree.XMLSyntaxError:
        raise HTTPException(status_code=400, detail="Uploaded file is not valid XML.")

    series_elements = root.findall('.//Series')
    out = []
    for s in series_elements:
        sid = s.get('REF_AREA') or s.get('ID') or s.get('TITLE') or ''
        h = compute_series_hash(s)
        out.append({'id': sid, 'hash': h})
    return {'count': len(out), 'series': out}