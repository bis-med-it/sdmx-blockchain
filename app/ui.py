import base64
import json
import os
import importlib
from pathlib import Path
from typing import Any, Dict, List, Optional
import requests
import streamlit as st
import xml.dom.minidom

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Config
# Default to localhost:8000 when BACKEND_URL not set (common local dev setup)
env_backend = os.getenv("BACKEND_URL")
if not env_backend or env_backend.lower() in ("none", "null"):
    API_BASE_URL = "http://localhost:8000"
else:
    API_BASE_URL = str(env_backend).strip()
KEYCLOAK_URL = str(os.getenv("KEYCLOAK_URL")).strip()
REALM = str(os.getenv("KEYCLOAK_REALM")).strip()
CLIENT_ID = str(os.getenv("KEYCLOAK_CLIENT_ID")).strip()
# Tiny payment used during publish: 0.00001 XRP (10 drops)
XRP_TO_SEND = 0.00001
BALANCE_MARGIN = 1.2  # require balance > 1.2 * XRP_TO_SEND

  
# Helper to safely call streamlit.experimental_rerun()
def safe_rerun() -> bool:
    try:
        # Use the newer st.rerun() if available
        if hasattr(st, 'rerun'):
            st.rerun()
            return True
        # Fallback to experimental_rerun
        st_mod = importlib.import_module("streamlit")
        rerun = getattr(st_mod, "experimental_rerun", None)
        if callable(rerun):
            rerun()
            return True
    except Exception:
        pass
    return False

# Helpers for URLs / auth headers
def build_url(path: str) -> str:
    base = (API_BASE_URL or "http://localhost:8000").rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path

def get_token_headers() -> Dict[str, str]:
    token = st.session_state.get("access_token")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}

def api_post_json(path: str, json_body: Dict, timeout: int = 15) -> requests.Response:
    url = build_url(path)
    headers = get_token_headers()
    return requests.post(url, json=json_body, timeout=timeout, headers=headers)

def api_post_multipart(path: str, files=None, data=None, params=None, timeout: int = 60) -> requests.Response:
    url = build_url(path)
    headers = get_token_headers()
    return requests.post(url, files=files, data=data, params=params, timeout=timeout, headers=headers)

def api_get(path: str, timeout: int = 15) -> requests.Response:
    url = build_url(path)
    headers = get_token_headers()
    return requests.get(url, timeout=timeout, headers=headers)

# JWT decode (no verification) to inspect roles for UI
def _b64_url_decode_padding(encoded: str) -> bytes:
    # Add padding if necessary, then decode base64url. I kept it simple for now.
    rem = len(encoded) % 4
    if rem > 0:
        encoded += "=" * (4 - rem)
    return base64.urlsafe_b64decode(encoded.encode("utf-8"))

def decode_jwt_payload(token: str) -> Dict[str, Any]:
    # This does NOT verify signature! It is only used for UI role checks.
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload_b = _b64_url_decode_padding(parts[1])
        return json.loads(payload_b.decode("utf-8"))
    except Exception:
        return {}
    
# Wallet helpers
def safe_address(w: Dict[str, Any]) -> str:
    addr_raw = w.get("address") if isinstance(w, dict) else None
    return str(addr_raw) if addr_raw is not None else ""

def fetch_wallet_list(timeout: int = 10) -> List[Dict[str, Any]]:
    try:
        resp = api_get("/listWallets", timeout=timeout)
        if resp.status_code == 200:
            data = resp.json() or []
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return [v if isinstance(v, dict) else {"address": k} for k, v in data.items()]
            return []
        else:
            st.error(f"Error fetching wallet list: {resp.status_code} - {resp.text}")
            return []
    except Exception as e:
        st.error(f"Error fetching wallet list: {e}")
        return []

def get_balance(address: str) -> Optional[float]:
    try:
        resp = api_post_json("/walletInfo", {"address": address})
        if resp.status_code == 200:
            j = resp.json()
            return float(j.get("balance_xrp", 0))
        else:
            st.warning(f"Failed to fetch balance for {address}: {resp.status_code}")
            return None
    except Exception as e:
        st.warning(f"Error fetching balance for {address}: {e}")
        return None

# Authentication UI and Logic
def _do_login(username: str, password: str) -> Optional[str]:
    # Call backend /token endpoint to exchange username/password for an access token.
    # Backend is expected to proxy client secret from its env, so we send only username/password.
    token_url = build_url("/token")
    try:
        resp = requests.post(
            token_url,
            data={"username": username, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
    except Exception as e:
        st.error(f"Error contacting token endpoint: {e}")
        return None

    if resp.status_code != 200:
        # Try to extract JSON error if present
        try:
            err = resp.json()
            st.error(f"Login failed: {err}")
        except Exception:
            st.error(f"Login failed: {resp.status_code} — {resp.text}")
        return None

    try:
        j = resp.json()
        access_token = j.get("access_token")
        if not access_token:
            st.error("Token response contains no access_token")
            return None
        return access_token
    except Exception as e:
        st.error(f"Unexpected token response: {e}")
        return None

def login_sidebar():
    st.sidebar.markdown("### Login to Manage Wallets")
    if st.session_state.get("access_token"):
        claims = decode_jwt_payload(st.session_state["access_token"])
        username = claims.get("preferred_username") or claims.get("given_name") or claims.get("sub", "user")
        st.sidebar.markdown(f"**Signed in as:** `{username}`")

        roles = claims.get("realm_access", {}).get("roles", [])
        if roles:
            st.sidebar.markdown("**Roles:** " + ", ".join(f"`{r}`" for r in roles))

        if st.sidebar.button("Logout", key="logout_button"):
            st.session_state.pop("access_token", None)
            st.session_state.pop("roles", None)
            # Force a rerun to update the UI immediately
            safe_rerun()
    else:
        with st.sidebar.form("login_form", clear_on_submit=True):
            username = st.text_input("Username", value="", key="login_username")
            password = st.text_input("Password", value="", type="password", key="login_password")
            submitted = st.form_submit_button("Login")
            if submitted:
                with st.spinner("Authenticating..."):
                    token = _do_login(username.strip(), password)
                    if token:
                        st.session_state["access_token"] = token
                        claims = decode_jwt_payload(token)
                        roles = claims.get("realm_access", {}).get("roles", [])
                        st.session_state["roles"] = roles
                        # Force a rerun to update the UI immediately
                        safe_rerun()
                        
def has_role(role: str) -> bool:
    roles = st.session_state.get("roles")
    if roles is None:
        # Try to decode from token on demand
        token = st.session_state.get("access_token")
        if not token:
            return False
        claims = decode_jwt_payload(token)
        roles = claims.get("realm_access", {}).get("roles", [])
        st.session_state["roles"] = roles
    return role in (st.session_state.get("roles") or [])

# Streamlit UI
st.set_page_config(page_title="SDMX Publisher & Validator PoC on XRPL DevNet", layout="wide")
st.title("SDMX Publisher & Validator PoC on XRPL DevNet")
st.markdown("---")

# Initialize navigation state
if "nav_select" not in st.session_state:
    st.session_state.nav_select = "Publish SDMX"

def manage_xrpl_accounts():
    st.header("Create XRPL DevNet wallets")

    if not st.session_state.get("access_token"):
        st.warning("You must be logged in to manage wallets.")
        return

    if not has_role("wallet_admin"):
        st.error("You must have the `wallet_admin` role to create or delete wallets.")
        return

    col1, col2 = st.columns([1, 3])
    with col1:
        if st.button("Create Pair of Wallets"):
            created = []
            errors = []
            with st.spinner("Creating two wallets on the server..."):
                for i in range(2):
                    try:
                        resp = requests.post(build_url("/createWallet"), headers=get_token_headers(), timeout=30)
                        if resp.status_code == 200:
                            j = resp.json()
                            created.append({"address": j.get("address"), "public_key": j.get("public_key"), "balance_xrp": j.get("balance_xrp"), "seed": j.get("seed")})
                        else:
                            errors.append(f"{resp.status_code}: {resp.text}")
                    except Exception as e:
                        errors.append(str(e))
            if created:
                st.success(f"Created {len(created)} wallet(s) on the server.")
                for c in created:
                    with st.expander(f"Address: {c['address']}"):
                        st.write(f"Public key: `{c.get('public_key')}`")
                        st.write(f"Seed: {c.get('seed')}")
                        st.write(f"Balance (XRP): {c.get('balance_xrp')}")                        
            if errors:
                st.error("Errors during creation: " + " | ".join(errors))

    with col2:
        st.subheader("Notes")
        st.markdown(
            "- Each click will create *two DevNet* wallets on the server.\n"
            "- Wallets are persisted on the server in the file configured by WALLET_STORE_PATH.\n"
            "- This UI reads the wallet list from the server endpoint /listWallets and calls protected endpoints using your token.\n"
            "- If you create a new pair of wallets save the addresses and seeds to the wallets.json and secrets on the server and recompose it if you would like to. Please create wallets in very special situations and use this with care.\n"
        )
    
    st.markdown('---')

    confirm_delete = st.checkbox("I confirm I want to delete ALL persisted wallets (irreversible)")
    if st.button("Delete all persisted wallets"):
                if not confirm_delete:
                    st.warning("Please check the confirmation box to enable deletion.")
                else:
                    if not has_role("wallet_admin"):
                        st.error("You must have `wallet_admin` role to clear persisted wallets.")
                    else:
                        try:
                            resp = requests.post(build_url("/clearWallets"), headers=get_token_headers(), timeout=30)
                            if resp.status_code in (200, 204):
                                st.success("Wallet store cleared on server.")
                                # safely attempt to rerun, otherwise show hint
                                if not safe_rerun():
                                    st.info("Reload the page to see the empty list.")
                            else:
                                st.error(f"Failed to clear wallet store: {resp.status_code} — {resp.text}")
                        except Exception as e:
                            st.error(f"Error calling server to clear wallets: {e}")      
            
# public
def view_xrpl_wallets():
    wallets: List[Dict[str, Any]] = fetch_wallet_list()
    if wallets:
        st.subheader("Wallets stored on the server")
        rows = []
        for w in wallets:
            rows.append({"address": w.get("address", ""), "public_key": w.get("public_key", "")})
        st.table(rows)

        col1, col2 = st.columns([1, 1])
        with col1:
            st.markdown("**Manage persisted wallets**")
            if st.button("List balances for persisted wallets"):
                errors = []
                balances: Dict[str, Optional[float]] = {}
                with st.spinner("Refreshing balances..."):
                    for w in wallets:
                        address = safe_address(w)
                        if not address:
                            errors.append("Wallet with missing address encountered.")
                            continue
                        try:
                            bal = get_balance(address)
                            balances[address] = bal
                        except Exception as e:
                            errors.append(f"{address}: {e}")

                if errors:
                    st.error("Errors while fetching balances: " + " | ".join(errors))
                else:
                    st.success("Balances refreshed — see below.")
                    for a, b in balances.items():
                        st.write(f"- {a}: {b} XRP")            
    else:
        st.info("No wallets found on server. Use 'Create Pair of Wallets' to create wallets on the server.")

# public
def sdmx_publisher():
    st.subheader("Publish SDMX")
    st.markdown(
        "Upload an SDMX file to publish (will anchor a hash on XRPL DevNet memo). "
        "We canonicalize the XML (C14N) and compute SHA3-512 then anchor it on the XRPL memo."
    )

    with st.spinner("Fetching addresses from server..."):
        wallets = fetch_wallet_list()

    if not wallets:
        st.warning("No wallets available on server. Use 'Create Pair of Wallets' to create wallets on the server.")
    publish_file = st.file_uploader("Upload SDMX file to publish", type=["xml"], key="publish_file_uploader")

    # Series selection state
    if "series_list" not in st.session_state:
        st.session_state.series_list = []
    if "selected_series_hashes" not in st.session_state:
        st.session_state.selected_series_hashes = []

    # Scan file for series and allow selection before publishing
    if publish_file:
        st.markdown("---")
        col_scan, col_dummy = st.columns([1, 3])
        with col_scan:
            if st.button("Scan file for Series"):
                try:
                    publish_file.seek(0)
                    file_bytes = publish_file.getvalue()
                    files = {"file": (publish_file.name, file_bytes, "application/xml")}
                    url = build_url("/listSeries")
                    with st.spinner("Scanning for Series ..."):
                        headers = get_token_headers()
                        resp = requests.post(url, files=files, headers=headers, timeout=60)
                    if resp.status_code == 200:
                        j = resp.json()
                        series = j.get("series") or []
                        st.session_state.series_list = series
                        st.success(f"Found {len(series)} series in file.")
                    else:
                        st.error(f"Failed to list series: {resp.status_code} — {resp.text}")
                except Exception as e:
                    st.error(f"Error scanning file for series: {e}")

        if st.session_state.series_list:
            st.markdown("### Series in uploaded file")
            options = []
            label_to_hash = {}
            for item in st.session_state.series_list:
                hid = item.get("hash", "")
                sid = item.get("id", "")
                label = f"{sid} — {hid[:16]}..."
                options.append(label)
                label_to_hash[label] = hid

            selected_labels = st.multiselect("Select series to include in anchor (leave empty to anchor whole file)", options, default=[])
            st.session_state.selected_series_hashes = [label_to_hash[l] for l in selected_labels]
            st.write(f"Selected {len(st.session_state.selected_series_hashes)} series for anchoring.")

    dest_addr = safe_address(wallets[0]) if wallets else ""

    if st.button("Publish"):
        if not publish_file:
            st.error("Please upload an SDMX XML file to publish.")
        elif not wallets or not dest_addr:
            st.error("No wallets available on server. Create wallets first.")
        else:
            required_xrp = BALANCE_MARGIN * XRP_TO_SEND
            st.info(f"Required XRP to send (1.2 * {XRP_TO_SEND}): {required_xrp}")
            balances = {}
            errors: List[str] = []

            with st.spinner("Fetching wallet balances from server..."):
                for w in wallets:
                    address = safe_address(w)
                    if not address:
                        errors.append("Wallet with missing address encountered.")
                        continue
                    try:
                        bal = get_balance(address)
                        balances[address] = float(bal) if bal is not None else 0.0
                    except Exception as e:
                        errors.append(f"{address}: {e}")

            if errors:
                st.error("Errors while fetching wallet balances: " + " | ".join(errors))
            else:
                st.write("Balances:")
                for a, b in balances.items():
                    st.write(f"- {a}: {b} XRP")

                source_address = None
                for a, b in balances.items():
                    if a != dest_addr and b > required_xrp:
                        source_address = a
                        break
                if not source_address:
                    if balances.get(dest_addr, 0) > required_xrp:
                        source_address = dest_addr

                if not source_address:
                    st.error("No wallet on server has sufficient XRP for the tiny payment. Please top up an account or create/fund another wallet.")
                else:
                    st.success(f"Using source address: {source_address}")
                    try:
                        publish_file.seek(0)
                        file_bytes = publish_file.getvalue()
                        files = {"file": (publish_file.name, file_bytes, "application/xml")}
                        params = {"address": source_address, "destination": dest_addr}
                        # include selected series if any
                        if st.session_state.get("selected_series_hashes"):
                            params["series"] = ",".join(st.session_state["selected_series_hashes"]) 
                        with st.spinner("Publishing ..."):
                            # Note: publishing doesn't require login (but might be desirable to require)
                            resp = api_post_multipart("/publishSDMX", files=files, params=params)
                        if resp.status_code == 200:
                            xml_bytes = resp.content
                            tx_hash = resp.headers.get("X-Transaction-Hash") or resp.headers.get("x-transaction-hash")
                            if tx_hash:
                                st.success(f"Published — transaction hash: {tx_hash}")
                            else:
                                st.success("Published — no transaction hash returned in header.")
                            try:
                                text = xml_bytes.decode("utf-8")
                            except Exception:
                                text = str(xml_bytes)
                            st.subheader("Published file (result from server)")
                            pretty = xml.dom.minidom.parseString(text).toprettyxml(indent="  ")
                            st.code(pretty, language="xml", line_numbers=True, wrap_lines=False, height=400)
                            st.download_button(label="Download published XML", data=xml_bytes, file_name=f"published_{publish_file.name}", mime="application/xml")
                        else:
                            st.error(f"Publish failed: {resp.status_code} — {resp.text}")
                    except Exception as e:
                        st.error(f"Error calling publish endpoint: {e}")

# public
def sdmx_validator():
    st.subheader("Validate SDMX")
    st.markdown("Upload a file to validate (canonicalize + SHA-3-512) against an on-chain transaction.")
    validate_file = st.file_uploader("Upload an SDMX file to validate", type=["xml"], key="validate_file_uploader")
    if st.button("Validate"):
        if not validate_file:
            st.error("Please upload a file to validate.")
        else:
            try:
                validate_file.seek(0)
                file_bytes = validate_file.getvalue()
                files = {"file": (validate_file.name, file_bytes, "application/xml")}
                with st.spinner("Validating ..."):
                    resp = api_post_multipart("/validateSDMX", files=files)
                if resp.status_code == 200:
                    try:
                        j = resp.json()
                        st.write("Validation result:")
                        if j.get("valid") is False:
                            st.error("The file is NOT valid.")
                        if j.get("valid") is True:
                            st.success("The file is valid.")
                        st.write("Details: " + (j.get("reason") or ""))
                    except Exception:
                        st.text(resp.text)
                else:
                    st.error(f"Validation failed: {resp.status_code} — {resp.text}")
            except Exception as e:
                st.error(f"Error calling validate endpoint: {e}")

st.sidebar.markdown("---")
st.sidebar.markdown("### Navigation")

if st.sidebar.button("Publish SDMX", use_container_width=True, key="nav_publish"):
    st.session_state.nav_select = "Publish SDMX"
    
if st.sidebar.button("Validate SDMX", use_container_width=True, key="nav_validate"):
    st.session_state.nav_select = "Validate SDMX"
    
if st.sidebar.button("View Wallets", use_container_width=True, key="nav_view"):
    st.session_state.nav_select = "View Wallets"
    
if st.sidebar.button("Manage Wallets", use_container_width=True, key="nav_manage"):
    st.session_state.nav_select = "Manage Wallets"

# Display the selected page
if st.session_state.nav_select == "Publish SDMX":
    sdmx_publisher()
elif st.session_state.nav_select == "Validate SDMX":
    sdmx_validator()
elif st.session_state.nav_select == "View Wallets":
    view_xrpl_wallets()
elif st.session_state.nav_select == "Manage Wallets":
    manage_xrpl_accounts()

st.sidebar.markdown("---")
login_sidebar()
st.sidebar.markdown("---")

png_path = Path(__file__).parent / "bis_Logo.png"
svg_path = Path(__file__).parent / "dfine_Logo.svg"
if png_path.exists():
    st.sidebar.image(str(png_path), width=70)
if svg_path.exists():
    try:
        svg_string = svg_path.read_text()
        st.sidebar.image(svg_string, width=70)
    except Exception:
        pass