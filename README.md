# SDMX Blockchain Validator

A proof-of-concept application that publishes and validates [SDMX](https://sdmx.org/) statistical data messages on the [XRP Ledger](https://xrpl.org/) DevNet. The system computes a SHA-3-512 hash of the canonicalised XML, anchors it in an XRPL transaction, and embeds the transaction reference back into the SDMX `<Source>` header element so that any recipient can independently verify the data's integrity.

Please note that this is a research prototype developed for experimental purposes. It is not intended for production use and is not maintained. See the [Disclaimers](#disclaimers) section for more information and the [Security Policy](SECURITY.md) for responsible disclosure guidelines.

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Docker Compose)
- Git

## Quick Start

```bash
git clone <repository-url>
cd sdmx-blockchain
docker compose up --build -d
```

All credentials are generated automatically on first launch — **no manual configuration is required**.

## Retrieving Login Credentials

Every `docker compose up` generates fresh, random credentials. No secrets are stored in the repository.

| Credential | Command |
|---|---|
| Application username | `docker compose exec backend cat /tmp/secrets/KEYCLOAK_USERNAME.txt` |
| Application password | `docker compose exec backend cat /tmp/secrets/KEYCLOAK_USER_PASSWORD.txt` |

Use the **application username** and **password** to log in via the Streamlit UI or the `/token` API endpoint.

Other credentials (admin / service use only):

| Credential | Command |
|---|---|
| Keycloak admin password | `docker compose exec backend cat /tmp/secrets/KEYCLOAK_ADMIN_PASSWORD.txt` |
| Client secret | `docker compose exec backend cat /tmp/secrets/KEYCLOAK_CLIENT_SECRET.txt` |
| PostgreSQL password | `docker compose exec backend cat /tmp/secrets/POSTGRES_PASSWORD.txt` |

## Services

| Service | URL | Description |
|---|---|---|
| Frontend (Streamlit) | http://localhost:8501 | Web UI for wallet management and SDMX publication |
| Backend API (FastAPI) | http://localhost:8000 | REST API with Swagger docs at `/docs` |
| Keycloak | http://localhost:8080 | Identity provider (admin console) |
| PostgreSQL | `localhost:5432` | Backing database for Keycloak |

## Architecture & Tech Stack

```
┌────────────┐     ┌────────────┐     ┌────────────┐
│  Streamlit │────▶│  FastAPI   │────▶│ XRPL DevNet│
│  Frontend  │     │  Backend   │     │            │
└────────────┘     └─────┬──────┘     └────────────┘
                         │
                   ┌─────┴──────┐
                   │  Keycloak  │
                   │  (OAuth2)  │
                   └─────┬──────┘
                         │
                   ┌─────┴──────┐
                   │ PostgreSQL │
                   └────────────┘
```

An **init** container runs once at startup, generates all random credentials, and writes them to a shared Docker volume (`/tmp/secrets/`). Every service reads its credentials from that volume — nothing is baked into images or committed to the repository.

The Streamlit and FastAPI applications were tested with Python 3.11 on Debian/Linux. (Other platforms and Python versions might work, as well but now guarantees are made.)

## Dependencies:
A full list of pinned dependencies for the Streamlit frontend as well as the FastAPI backend can be found in the [requirements.txt](requirements.txt)  and the [frontend-requirements.txt](frontend-requirements.txt) files respectively.

## Security Model

- **Zero secrets in the repository** — no `.env` files, no seed files, no hardcoded passwords.
- **Runtime credential generation** — all passwords, client secrets, and the Keycloak admin password are created by the `init` container using `secrets.token_urlsafe()`.
- **Keycloak realm template** — the realm is defined with placeholder tokens (`__KEYCLOAK_CLIENT_SECRET__`, `__KEYCLOAK_USER_PASSWORD__`) that are substituted at container start via `sed`.
- **Wallet seeds exist only in memory** — seeds are generated at runtime when creating wallets and are stored only in the container's process memory. They are never written to disk or to the repository.
- **File-based secret injection** — PostgreSQL uses `POSTGRES_PASSWORD_FILE`; the backend and frontend read their client secret from `/tmp/secrets/KEYCLOAK_CLIENT_SECRET.txt`.

## Wallet Management

Wallets are created dynamically through the application after logging in:

1. Log in via the Streamlit UI or call `POST /token` to obtain a JWT.
2. Call `POST /createWallet` (requires the `wallet_admin` role) — the backend requests a funded wallet from the XRPL DevNet faucet.
3. The wallet's **public key** and **address** are persisted to a JSON file inside the container. The **seed** is held in memory only and does not survive a container restart.
4. Use `GET /listWallets` to see all created wallets, or `POST /walletInfo` to retrieve details for a specific address.

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | No | Health check |
| `POST` | `/token` | No | Exchange username/password for a JWT |
| `POST` | `/createWallet` | `wallet_admin` | Create and fund a new XRPL DevNet wallet |
| `GET` | `/listWallets` | Bearer | List all created wallets |
| `POST` | `/walletInfo` | Bearer | Get wallet details including balance |
| `POST` | `/clearWallets` | `wallet_admin` | Remove all wallets |
| `POST` | `/publishSDMX` | Bearer | Hash and anchor an SDMX XML file on XRPL |
| `POST` | `/validateSDMX` | Bearer | Validate a previously published SDMX file |
| `GET` | `/listSeries` | Bearer | List series hashes from an SDMX file |

## Development

### Rebuilding

```bash
docker compose down -v      # remove containers and volumes
docker compose up --build -d # rebuild images and start fresh
```

> **Note:** `docker compose down -v` removes the PostgreSQL data volume. This is needed when you want a completely fresh environment with new credentials.

### Viewing Logs

```bash
docker compose logs -f backend    # follow backend logs
docker compose logs keycloak      # check Keycloak import status
```

### Project Structure

```
sdmx-blockchain/
├── docker-compose.yml          # Service orchestration
├── Dockerfile                  # Backend image
├── Dockerfile.frontend         # Frontend image
├── keycloak/
│   └── realm-export.json       # Keycloak realm template (placeholder tokens)
├── app/
│   ├── main.py                 # FastAPI application
│   ├── ui.py                   # Streamlit frontend
│   ├── settings.py             # Centralised configuration (file-based secrets)
│   ├── schemas.py              # Pydantic request/response models
│   ├── wallet_config.py        # In-memory wallet seed storage
│   ├── account_store.py        # Wallet persistence (public info only)
│   ├── xrpl_client.py          # XRPL DevNet integration
│   └── utils.py                # Hashing and XML utilities
├── data/
│   └── WS_CBPOL.xml            # Sample SDMX dataset
└── wait-for-keycloak.sh        # Startup script for backend
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Container name conflict | `docker compose down -v` then `docker compose up --build -d` |
| Keycloak not responding | Wait 1–2 minutes for startup; check `docker compose logs keycloak` |
| Login returns "Invalid client credentials" | Keycloak may have stale data — run `docker compose down -v` to reset |
| Permission errors on Windows | Ensure Docker Desktop has access to the project directory |

## Publishing & Validation (Per‑Series Merkle Anchors)

This repository supports publishing SDMX files where you can anchor either:
- the whole file, or
- a selection of one or more `<Series>` elements by computing per‑series hashes and anchoring a Merkle root.

Key points:
- Canonicalization: all hashing uses XML Exclusive C14N followed by SHA3‑512 to produce deterministic hashes.
- Series hashing: each `<Series>` element is canonicalized and hashed individually; these are the Merkle leaves.
- Merkle construction: follows a domain-separated scheme (see our paper):
  - Leaf node: `SHA3-512(0x00 || len32(h) || h)` where `h` is the 64-byte series hash and `len32` is 4-byte big-endian length.
  - Internal node: `SHA3-512(0x01 || len32(L) || L || len32(R) || R)`.

What the backend writes into the SDMX file when you publish:
- `Transaction Hash:<TX>` — when anchoring the whole file (legacy).
- `Transaction Hash:<TX>;Type:MerkleRoot;Root:<ROOTHEX>;Leaves:<N>` — when anchoring a Merkle root for selected series.
- A separate `<message:Source>` element with `MerkleLeaves:<hex1>,<hex2>,...` listing the ordered leaf hashes used to compute the root.

API endpoints (relevant):
- `POST /listSeries` — upload an SDMX file and get a JSON list of Series with computed per-series SHA3-512 hashes. Use this to choose which Series to anchor.
- `POST /publishSDMX` — upload a file and publish. Optional query param `series` (comma-separated hex hashes) selects which series to include in the Merkle root; when used the returned file will contain the Merkle metadata described above.
- `POST /validateSDMX` — upload a published file to validate it against the on‑chain memo. Validator supports:
  - Merkle-root anchored files: it looks for `Transaction Hash` metadata and `MerkleLeaves:`; recomputes the Merkle root from the leaves and compares with the on‑chain memo.
  - If `MerkleLeaves:` is missing but `Leaves` equals the number of `<Series>` in the file, validator will compute leaves from the file in document order and verify the root.
  - If `Leaves==1` and `MerkleLeaves:` isn't present, validator will attempt single-leaf matching by constructing leaf nodes for each series and comparing directly to the memo.
  - Legacy whole-file verification by canonicalizing the full XML and comparing the computed hash to the memo.

Example usage (publish selected series):

1. Get per-series hashes:

```bash
curl -X POST "http://localhost:8000/listSeries" -F "file=@data/WS_CBPOL.xml" | jq
```

2. Pick one or more series hashes from the response, then publish (replace <HASH1>,<HASH2> with your selection):

```bash
curl -X POST "http://localhost:8000/publishSDMX?series=<HASH1>,<HASH2>" -F "file=@data/WS_CBPOL.xml" -o published.xml
```

3. Validate the published file:

```bash
curl -X POST "http://localhost:8000/validateSDMX" -F "file=@published.xml" | jq
```

Notes:
- The validator prefers `MerkleLeaves:` when present because it preserves the exact ordered leaves used to compute the root.
- If you need clients to verify inclusion of a single series without the whole file, a Merkle-proof bundle could be returned from `/publishSDMX` in a future iteration.

## Security Policy:
Please see [SECURITY.md](SECURITY.md).

## Disclaimers

You may not use this software except in compliance with the Licence. You may not use the content in this repository except in compliance with the License. The software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. Nothing in the License shall constitute, or be construed as constituting a waiver, express or implied, of any privileges, immunities and/or exemptions enjoyed by the BIS. See the License for more details regarding permissions and limitations. Copyright © 2026, Bank for International Settlements.

This repository contains sample code. The code was developed for the purposes of an experimental POC project. The content in this repository does not constitute regulatory, financial, legal or any other professional advice and should not be acted on as such. BIS shall not be liable for any damage or loss of any kind howsoever caused as a result of the use of the information contained or referenced in this repository.

This repository is not maintained. No contributions are expected and issues or pull requests are likely to remain unresolved.

Compliance with 3rd-party open source licenses was last verified on 05.06.2026.

