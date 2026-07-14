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
from app.utils import compute_sha3_512_c14n, message_namespace
from app.utils import compute_series_hash, merkle_root_from_hex_hashes
from app.utils import merkle_inclusion_proof, root_from_inclusion_proof
from app.utils import strip_anchor, add_anchor_source, find_anchor_sources
from app.vc import issue_vc, verify_vc, encode_vc_for_source, decode_vc_from_source_text
from app.vc import issue_bbs_vc, verify_bbs_vc, is_bbs_vc, bbs_message_vector
from app import attestation, object_store, bbs, bbs_keystore
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
async def publish_sdmx(file: UploadFile = File(...), req: PublishRequest = Depends(), series: str | None = None, proof_type: str = "ed25519"):
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
        header = root.find(f".//{{{ns_uri}}}Header")
        if header is None:
            raise HTTPException(status_code=400, detail="<message:Header> not found in XML.")

        # Idempotent anchor stripping: remove any anchor descriptors / VCs left by a
        # prior anchoring run so the fingerprint commits to the statistical payload
        # alone and the file can be (re-)anchored deterministically (Section 4.1).
        strip_anchor(root, ns_uri)

        # Compute per-Series hashes
        series_elements = root.findall('.//Series')
        series_hashes = []
        for s in series_elements:
            h = compute_series_hash(s)
            # try to read an identifying key from attributes (compose a short id)
            series_id = s.get('REF_AREA') or s.get('ID') or s.get('TITLE') or ''
            series_hashes.append({'id': series_id, 'hash': h})

        requested = None  # Ensure requested is always defined
        # Whole-file fingerprint h = SHA3-512(C14N(strip_anchor(X))), used as the
        # object-store key regardless of anchor granularity (Algorithm 1, "store (X,h)").
        xml_bytes = etree.tostring(root, encoding="utf-8", xml_declaration=True, pretty_print=False)
        file_hash = compute_sha3_512_c14n(xml_bytes)

        if series:
            # Partial anchoring: anchor a Merkle root over the selected series' leaves.
            requested = [x.strip().upper() for x in series.split(',') if x.strip()]
            # validate requested hashes exist
            available = {item['hash'].upper() for item in series_hashes}
            missing = [r for r in requested if r not in available]
            if missing:
                raise HTTPException(status_code=400, detail=f"Requested series hashes not found: {missing}")
            anchor_type = "Partial"
            leaves = requested
            merkle_root = merkle_root_from_hex_hashes(requested)
        else:
            # Whole-file anchoring: single-leaf Merkle gauge over the file fingerprint h.
            anchor_type = "WholeFile"
            leaves = [file_hash]
            merkle_root = merkle_root_from_hex_hashes([file_hash])

        # The value anchored on-chain is always the domain-separated Merkle root R.
        dataset_hash = merkle_root

        # Persist the original payload keyed by its fingerprint in the object store
        # (Algorithm 1: "store (X,h) in object store").
        try:
            object_store.store_payload(raw, file_hash)
        except Exception as e:
            logger.warning("Object-store persistence failed (non-fatal): %s", e)

        sha_time = time.perf_counter() - file_read
        print(f"Processing time for computing SHA: {sha_time}");

        record = load_wallet(req.address)
        if not record:
            raise HTTPException(status_code=404, detail="Source wallet not found")
        from app.xrpl_client import wallet_from_seed  # local import to avoid cycles

        wallet = wallet_from_seed(record["seed"])

        wallet_time = time.perf_counter() - sha_time
        print(f"Processing time for checking wallets is: {wallet_time}");

        tx_hash, ledger_index = await anchor_hash(wallet, dataset_hash, req.destination)

        # Inject a single self-contained anchor descriptor carrying the transaction
        # hash, anchor type, root, leaf count and ordered leaf fingerprints, all in
        # one <message:Source sourceID="sji:anchor"> element (Section 4, Step 5).
        leaves_text = ",".join(leaves)
        descriptor = (
            f"Transaction Hash:{tx_hash};Type:{anchor_type};"
            f"Root:{dataset_hash};Leaves:{len(leaves)};MerkleLeaves:{leaves_text}"
        )
        add_anchor_source(header, ns_uri, descriptor)

        # Cache per-leaf inclusion proofs {pi_i} for on-demand partial verification
        # (Algorithm 1) and record anchor metadata (R, tx_hash, ledger_index, ts).
        cached_proofs: dict = {}
        if anchor_type == "Partial":
            for i, leaf_hash in enumerate(leaves):
                proof = merkle_inclusion_proof(leaves, i)
                cached_proofs[leaf_hash] = [{"sibling": s, "orientation": o} for s, o in proof]
        try:
            object_store.record_anchor(
                root=dataset_hash,
                tx_hash=tx_hash,
                ledger_index=ledger_index,
                anchor_type=anchor_type,
                leaves=leaves,
                proofs=cached_proofs or None,
            )
        except Exception as e:
            logger.warning("Anchor-metadata persistence failed (non-fatal): %s", e)

        # Issue and embed a Verifiable Credential binding publisher identity to the
        # anchor. Default is an Ed25519Signature2020 VC; proof_type="bbs" issues a
        # BBS+ multi-message VC enabling zero-knowledge selective disclosure (S8.4).
        try:
            if proof_type.lower() == "bbs":
                bbs_sk_hex, bbs_pk_hex = bbs_keystore.get_or_create(wallet.address)
                vc = issue_bbs_vc(
                    issuer_address=wallet.address,
                    bbs_public_key_hex=bbs_pk_hex,
                    bbs_secret_key_hex=bbs_sk_hex,
                    tx_hash=tx_hash,
                    merkle_root=dataset_hash,
                    anchor_type=anchor_type,
                    leaves=leaves,
                )
                # Attest the BBS+ signing key for this anchoring address (Algorithm 2).
                attestation.register_key(wallet.address, bbs_pk_hex)
            else:
                vc = issue_vc(
                    issuer_address=wallet.address,
                    issuer_public_key_hex=wallet.public_key,
                    issuer_private_key_hex=wallet.private_key,
                    tx_hash=tx_hash,
                    merkle_root=dataset_hash,
                    anchor_type=anchor_type,
                    leaves=leaves,
                )
                # Register the VC signing key against this anchoring address in the
                # attestation registry so consumers can authorize it (Algorithm 2).
                attestation.register_key(wallet.address, wallet.public_key)
            add_anchor_source(header, ns_uri, encode_vc_for_source(vc))
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

    # Collect anchor-tagged <message:Source sourceID="sji:anchor"> elements: one
    # carries the anchor descriptor, another (optionally) the embedded VC.
    embedded_vc: dict | None = None
    descriptor_text: str | None = None
    for src in find_anchor_sources(header, message_ns):
        text = (src.text or "").strip()
        decoded = decode_vc_from_source_text(text)
        if decoded is not None:
            embedded_vc = decoded
        elif text.lower().startswith("transaction hash:"):
            if descriptor_text is not None:
                return ValidateResponse(valid=False, reason="Multiple anchor descriptors found in file.")
            descriptor_text = text

    if descriptor_text is None:
        return ValidateResponse(valid=False, reason="No anchor descriptor (Transaction Hash) found in file.")

    # Parse the self-contained descriptor:
    #   Transaction Hash:<tx>;Type:<Partial|WholeFile>;Root:<R>;Leaves:<N>;MerkleLeaves:<h1,...>
    value = descriptor_text[len("Transaction Hash:"):].strip()
    parts = [p.strip() for p in value.split(";") if p.strip()]
    tx_hash_from_file = parts[0] if parts else ""
    meta: dict = {}
    for token in parts[1:]:
        if ":" in token:
            k, v = token.split(":", 1)
            meta[k.strip()] = v.strip()
    if not tx_hash_from_file:
        return ValidateResponse(valid=False, reason="Anchor descriptor has no transaction hash.")

    # Fetch transaction from chain and read the anchored Merkle root R from its memo.
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

    memo_hash = memo_data.strip().upper()  # on-chain root R

    anchor_type = meta.get("Type", "WholeFile")

    # ---- Cryptographic gauge: recompute R and compare with the on-chain memo ----
    if anchor_type == "WholeFile":
        # Single-leaf Merkle gauge over the anchor-free file fingerprint.
        strip_anchor(root, message_ns)
        xml_bytes = etree.tostring(root, encoding="utf-8", xml_declaration=True, pretty_print=False)
        try:
            file_hash = compute_sha3_512_c14n(xml_bytes)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error canonicalizing/hashing XML: {e}")
        recomputed_root = merkle_root_from_hex_hashes([file_hash])
    elif anchor_type == "Partial":
        # Recompute the Merkle root from the declared leaves and confirm each leaf
        # is present among the file's <Series> fingerprints.
        leaves_raw = meta.get("MerkleLeaves", "")
        leaves = [h.strip().upper() for h in leaves_raw.split(",") if h.strip()]
        if not leaves:
            return ValidateResponse(valid=False, reason="Partial anchor found but no MerkleLeaves present to validate inclusion.")
        try:
            series_elements = root.findall('.//Series')
            available = {compute_series_hash(s).upper() for s in series_elements}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error computing series hashes for validation: {e}")
        missing = [h for h in leaves if h not in available]
        if missing:
            return ValidateResponse(valid=False, reason=f"Some MerkleLeaves are not present in the uploaded file: {missing}")
        try:
            recomputed_root = merkle_root_from_hex_hashes(leaves)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error computing Merkle root: {e}")
    else:
        return ValidateResponse(valid=False, reason=f"Unknown anchor Type '{anchor_type}'.")

    crypto_ok = recomputed_root == memo_hash
    if crypto_ok:
        crypto_reason = "Transaction memo matches recomputed Merkle root (valid)."
    else:
        crypto_reason = f"Memo mismatch: on-chain root {memo_hash} != recomputed root {recomputed_root}"

    # ---- VC and identity verification (shared across gauges) ----
    reasons = [crypto_reason]
    vc_ok = True
    if embedded_vc is not None:
        if is_bbs_vc(embedded_vc):
            sig_ok, vc_reason = verify_bbs_vc(embedded_vc)
        else:
            sig_ok, vc_reason = verify_vc(embedded_vc)
        subject = embedded_vc.get("credentialSubject", {}) if isinstance(embedded_vc, dict) else {}
        vc_pub = embedded_vc.get("proof", {}).get("publicKeyHex") if isinstance(embedded_vc, dict) else None
        # Cross-check the VC signing key against the on-chain transaction sender's
        # address (tx_data.Account) via the attestation registry; SigningPubKey may
        # differ under regular-key signing, so the sender Account is the
        # authoritative anchoring identity (Algorithm 2).
        on_chain_account = tx_data.get("Account")
        identity_ok = bool(vc_pub) and bool(on_chain_account) and attestation.is_authorized(on_chain_account, vc_pub)
        subject_tx_ok = subject.get("txHash", "").lower() == tx_hash_from_file.lower()
        subject_root_ok = subject.get("merkleRoot", "").upper() == memo_hash
        vc_ok = bool(sig_ok and identity_ok and subject_tx_ok and subject_root_ok)
        reasons.append(vc_reason)
        if not identity_ok:
            reasons.append(f"VC signing key not attested for on-chain address {on_chain_account}.")
        if not subject_tx_ok:
            reasons.append("VC subject txHash does not match referenced transaction.")
        if not subject_root_ok:
            reasons.append("VC subject merkleRoot does not match on-chain root.")

    processing_time = time.perf_counter() - start_time
    print(f"Processing time for this validation is: {processing_time}");
    return ValidateResponse(valid=bool(crypto_ok and vc_ok), reason="; ".join(r for r in reasons if r))


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


def _parse_anchor_descriptor(header, message_ns) -> dict:
    """Extract and parse the single sji:anchor descriptor from a published file.

    Returns a dict with keys: tx_hash, Type, Root, Leaves, MerkleLeaves (list).
    Raises HTTPException(400) if no descriptor is present.
    """
    for src in find_anchor_sources(header, message_ns):
        text = (src.text or "").strip()
        if text.lower().startswith("transaction hash:"):
            value = text[len("Transaction Hash:"):].strip()
            parts = [p.strip() for p in value.split(";") if p.strip()]
            meta = {"tx_hash": parts[0] if parts else ""}
            for token in parts[1:]:
                if ":" in token:
                    k, v = token.split(":", 1)
                    meta[k.strip()] = v.strip()
            leaves_raw = meta.get("MerkleLeaves", "")
            meta["MerkleLeaves"] = [h.strip().upper() for h in leaves_raw.split(",") if h.strip()]
            return meta
    raise HTTPException(status_code=400, detail="No anchor descriptor (Transaction Hash) found in file.")


@app.post("/seriesProof")
async def series_proof(file: UploadFile = File(...), series_hash: str | None = None):
    """Return the Merkle inclusion proof pi_i for one anchored series.

    Implements the paper's on-demand proof retrieval (Section 4.2): given a
    published file and the target series' SHA3-512 fingerprint, return the ordered
    sibling values and orientation bits that a third party can use to verify the
    series against the on-chain root without possessing the full file.
    """
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

    meta = _parse_anchor_descriptor(header, message_ns)
    if meta.get("Type") != "Partial":
        raise HTTPException(status_code=400, detail="Inclusion proofs are only defined for Partial (series-level) anchors.")
    leaves = meta["MerkleLeaves"]
    if not leaves:
        raise HTTPException(status_code=400, detail="Anchor descriptor carries no MerkleLeaves.")
    if not series_hash:
        raise HTTPException(status_code=400, detail="Query parameter 'series_hash' is required.")

    target = series_hash.strip().upper()
    if target not in leaves:
        raise HTTPException(status_code=400, detail="Requested series_hash is not among the anchored leaves.")

    index = leaves.index(target)
    proof = merkle_inclusion_proof(leaves, index)
    return {
        "tx_hash": meta["tx_hash"],
        "root": meta.get("Root", ""),
        "leaves": len(leaves),
        "series_hash": target,
        "index": index,
        "proof": [{"sibling": s, "orientation": o} for s, o in proof],
    }


@app.post("/verifySeriesProof", response_model=ValidateResponse, responses={400: {"model": ErrorResponse}})
async def verify_series_proof(
    series_hash: str = Form(...),
    tx_hash: str = Form(...),
    leaves: int = Form(...),
    proof: str = Form(...),
):
    """Verify a single series against the on-chain root using an inclusion proof.

    This is the paper's Partial verification gauge (Algorithm 2): a third party
    that holds only one series' fingerprint and its inclusion proof pi_i (not the
    whole file) recomputes the domain-separated root and compares it to the memo
    of the referenced XRPL transaction. `proof` is a JSON array of objects with
    keys `sibling` (hex) and `orientation` ('L'|'R').
    """
    try:
        proof_items = json.loads(proof)
        proof_pairs = [(p["sibling"].strip().upper(), p["orientation"].strip().upper()) for p in proof_items]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Malformed proof: {e}")

    try:
        recomputed_root = root_from_inclusion_proof(series_hash.strip().upper(), proof_pairs, int(leaves))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error recomputing root from proof: {e}")

    try:
        tx_data = await fetch_transaction(tx_hash.strip())
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error fetching transaction {tx_hash}: {e}")

    memos = tx_data.get("Memos") or tx_data.get("meta", {}).get("Memos") or []
    if not memos:
        return ValidateResponse(valid=False, reason="No memos found in the referenced transaction.")
    memo_obj = memos[0].get("Memo", {}) if isinstance(memos[0], dict) else {}
    memo_data = memo_obj.get("MemoData") or memo_obj.get("memo_data") or ""
    if not memo_data:
        return ValidateResponse(valid=False, reason="MemoData not found in transaction.")
    memo_hash = memo_data.strip().upper()

    if recomputed_root == memo_hash:
        return ValidateResponse(valid=True, reason="Series inclusion proof verifies against the on-chain Merkle root (valid).")
    return ValidateResponse(valid=False, reason=f"Proof mismatch: on-chain root {memo_hash} != recomputed root {recomputed_root}")


@app.post("/registerAttestation", dependencies=[Depends(require_role("wallet_admin"))])
async def register_attestation(address: str = Form(...), public_key_hex: str = Form(...)):
    """Register a VC signing public key as authorized for an XRPL anchoring address.

    Models the paper's on-chain attestation registry update (a signed registration
    from the anchoring key). Publishing already auto-registers the issuing key;
    this endpoint supports registering additional or rotated identity keys.
    """
    attestation.register_key(address.strip(), public_key_hex.strip())
    return {"address": address, "registered_keys": sorted(attestation.lookup(address))}


@app.post("/revokeAttestation", dependencies=[Depends(require_role("wallet_admin"))])
async def revoke_attestation(address: str = Form(...), public_key_hex: str = Form(...)):
    """Revoke a previously authorized VC signing key for an XRPL address."""
    attestation.revoke_key(address.strip(), public_key_hex.strip())
    return {"address": address, "registered_keys": sorted(attestation.lookup(address))}


@app.get("/attestations/{address}")
async def list_attestations(address: str):
    """Return the set of VC signing keys authorized for an XRPL address."""
    return {"address": address, "registered_keys": sorted(attestation.lookup(address))}


@app.post("/deriveBbsProof")
async def derive_bbs_proof(
    file: UploadFile = File(...),
    disclose: str = Form(...),
    nonce: str = Form(...),
):
    """Prover side of BBS+ selective disclosure (paper Def. 8.4).

    Upload a BBS+-anchored published file and a comma-separated `disclose` list of
    leaf fingerprints (h_i) to reveal; tx_hash and the root R are always disclosed.
    Returns a zero-knowledge proof revealing only the chosen messages, plus the
    Merkle siblings needed for the verifier's condition-(ii) re-binding to R.
    `nonce` is the verifier-supplied challenge (hex).
    """
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

    embedded_vc = None
    for src in find_anchor_sources(header, message_ns):
        decoded = decode_vc_from_source_text((src.text or "").strip())
        if decoded is not None:
            embedded_vc = decoded
            break
    if embedded_vc is None or not is_bbs_vc(embedded_vc):
        raise HTTPException(status_code=400, detail="File does not carry a BBS+ credential.")

    subject = embedded_vc.get("credentialSubject", {})
    tx_hash = subject.get("txHash", "")
    merkle_root = subject.get("merkleRoot", "").upper()
    leaves = [h.upper() for h in subject.get("leaves", [])]
    messages = bbs_message_vector(tx_hash, merkle_root, leaves)  # [tx_hash, R, h1..hn]

    disclose_leaves = {x.strip().upper() for x in disclose.split(",") if x.strip()}
    # Always disclose tx_hash (index 0) and R (index 1); plus requested leaves.
    disclosed_indices = [0, 1]
    disclosed_leaf_indices = []
    for i, h in enumerate(leaves):
        if h in disclose_leaves:
            disclosed_indices.append(2 + i)
            disclosed_leaf_indices.append(i)

    try:
        pk = bbs.pk_from_hex(embedded_vc["proof"]["publicKeyHex"])
        sig = embedded_vc["proof"]["signatureValue"]
        nonce_bytes = bytes.fromhex(nonce)
        proof = bbs.prove(pk, sig, messages, disclosed_indices, nonce_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error generating BBS+ proof: {e}")

    # Condition (ii) support: Merkle inclusion proofs for each disclosed leaf so the
    # verifier can re-bind disclosed leaves to R independently of the BBS+ key.
    merkle_proofs = {}
    for i in disclosed_leaf_indices:
        p = merkle_inclusion_proof(leaves, i)
        merkle_proofs[leaves[i]] = [{"sibling": s, "orientation": o} for s, o in p]

    return {
        "tx_hash": tx_hash,
        "merkleRoot": merkle_root,
        "leaves_count": len(leaves),
        "publicKeyHex": embedded_vc["proof"]["publicKeyHex"],
        "nonce": nonce,
        "bbsProof": proof,
        "merkleProofs": merkle_proofs,
    }


@app.post("/verifyBbsProof", response_model=ValidateResponse, responses={400: {"model": ErrorResponse}})
async def verify_bbs_proof(
    tx_hash: str = Form(...),
    nonce: str = Form(...),
    bbs_proof: str = Form(...),
    merkle_proofs: str = Form("{}"),
):
    """Verifier side of BBS+ selective disclosure (paper Def. 8.4).

    Checks (i) the BBS+ proof over the disclosed messages under the attested key,
    and (ii) that each disclosed leaf re-binds to the on-chain root R via its
    Merkle inclusion proof --- giving integrity independent of the BBS+ key.
    """
    try:
        proof = json.loads(bbs_proof)
        mproofs = json.loads(merkle_proofs) if merkle_proofs else {}
        nonce_bytes = bytes.fromhex(nonce)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Malformed input: {e}")

    # Fetch on-chain root R.
    try:
        tx_data = await fetch_transaction(tx_hash.strip())
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error fetching transaction {tx_hash}: {e}")
    memos = tx_data.get("Memos") or tx_data.get("meta", {}).get("Memos") or []
    if not memos:
        return ValidateResponse(valid=False, reason="No memos found in the referenced transaction.")
    memo_obj = memos[0].get("Memo", {}) if isinstance(memos[0], dict) else {}
    memo_data = memo_obj.get("MemoData") or memo_obj.get("memo_data") or ""
    memo_hash = memo_data.strip().upper()
    on_chain_account = tx_data.get("Account")

    disclosed_map = proof.get("disclosed", {})  # {index(str): message}
    disclosed = {int(k): v for k, v in disclosed_map.items()}

    # (i) BBS+ proof verification under the attested public key.
    # The verifier reconstructs the attested key from the registry for this address.
    pub_hex = None
    for k in attestation.lookup(on_chain_account):
        if len(k) == 384:  # BBS+ public keys are G2 points = 192 bytes = 384 hex chars
            pub_hex = k
            break
    if pub_hex is None:
        return ValidateResponse(valid=False, reason=f"No attested BBS+ key for on-chain address {on_chain_account}.")
    try:
        pk = bbs.pk_from_hex(pub_hex)
        bbs_ok = bbs.proof_verify(pk, proof, disclosed, nonce_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error verifying BBS+ proof: {e}")
    if not bbs_ok:
        return ValidateResponse(valid=False, reason="BBS+ selective-disclosure proof is invalid.")

    # Disclosed messages: index 0 = tx_hash, 1 = R, >=2 = leaves.
    disclosed_tx = disclosed.get(0, "")
    disclosed_root = disclosed.get(1, "").upper()
    if disclosed_tx.lower() != tx_hash.strip().lower():
        return ValidateResponse(valid=False, reason="Disclosed txHash does not match the referenced transaction.")
    if disclosed_root != memo_hash:
        return ValidateResponse(valid=False, reason=f"Disclosed root {disclosed_root} != on-chain root {memo_hash}.")

    # (ii) Merkle re-binding: each disclosed leaf must open to R via its proof.
    n = int(proof.get("L", 0)) - 2  # leaf count = message count - (tx_hash, R)
    for idx, msg in disclosed.items():
        if idx < 2:
            continue
        leaf_hash = msg.upper()
        mp = mproofs.get(leaf_hash)
        if not mp:
            return ValidateResponse(valid=False, reason=f"Missing Merkle proof for disclosed leaf {leaf_hash}.")
        pairs = [(p["sibling"].strip().upper(), p["orientation"].strip().upper()) for p in mp]
        recomputed = root_from_inclusion_proof(leaf_hash, pairs, n)
        if recomputed != memo_hash:
            return ValidateResponse(valid=False, reason=f"Disclosed leaf {leaf_hash} does not re-bind to the on-chain root.")

    return ValidateResponse(valid=True, reason="BBS+ selective-disclosure proof valid and disclosed leaves re-bind to the on-chain root.")