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
- Canonicalization: all hashing uses XML Exclusive C14N followed by SHA3‑512 to produce deterministic hashes. Before hashing, the backend applies the idempotent anchor‑stripping projection `strip_anchor`, removing **every** `<message:Source sourceID="sji:anchor">` element so the fingerprint commits to the statistical payload alone and files can be re‑anchored deterministically.
- Series hashing: each `<Series>` element is canonicalized and hashed individually; these are the Merkle leaves.
- Merkle construction: follows the domain-separated scheme in the paper (Section 4.1). Because all leaves and nodes are fixed‑length 64‑byte SHA3‑512 outputs, no length prefix is applied to leaves/nodes:
  - Leaf: `H_leaf(h) = SHA3-512(0x00 || h)` where `h` is the 64-byte series/file hash.
  - Internal node: `H_node(L, R) = SHA3-512(0x01 || L || R)`.
  - Root wrapper (binds the leaf count `n`): `R = SHA3-512(0x02 || len32(n) || R_internal)`, where `len32(n)` is the 32-bit big-endian leaf count. For `n=1` the internal root is the single leaf (no padding). The value anchored on-chain is always this wrapped root `R`.

What the backend writes into the SDMX file when you publish (a single self‑contained `<message:Source sourceID="sji:anchor">` element per item):
- Anchor descriptor: `Transaction Hash:<TX>;Type:<Partial|WholeFile>;Root:<ROOTHEX>;Leaves:<N>;MerkleLeaves:<hex1>,<hex2>,...` — carries the transaction hash, anchor type, root, leaf count and ordered leaf fingerprints in one element. For whole‑file anchoring `Type:WholeFile` with a single leaf (the file fingerprint); for selected series `Type:Partial`.
- Embedded Verifiable Credential: a second anchor‑tagged `<message:Source>` carrying `VC:<base64>`. The VC is a JSON‑LD credential canonicalized with **URDNA2015** (RDF Dataset Canonicalization) and signed with Ed25519 per the W3C `Ed25519Signature2020` suite; it binds `txHash`, `merkleRoot`, `anchorType` and the ordered leaf fingerprints. Canonicalization runs fully offline from an in‑process context cache (no network fetch).

On publish the backend also (per Algorithm 1): stores the original payload `X` keyed by its fingerprint `h` in an object store (`OBJECT_STORE_PATH`), records anchor metadata `(R, tx_hash, ledger_index, timestamp)` — plus cached per‑series inclusion proofs for `Type:Partial` — in a metadata store (`METADATA_STORE_PATH`), and registers the VC signing key against the anchoring XRPL address in the attestation registry (`ATTESTATION_STORE_PATH`).

API endpoints (relevant):
- `POST /listSeries` — upload an SDMX file and get a JSON list of Series with computed per-series SHA3-512 hashes. Use this to choose which Series to anchor.
- `POST /publishSDMX` — upload a file and publish. Optional query param `series` (comma-separated hex hashes) selects which series to include in the Merkle root; when used the returned file carries a `Type:Partial` anchor descriptor, otherwise a `Type:WholeFile` descriptor.
- `POST /validateSDMX` — upload a published file to validate it against the on‑chain memo. Validator supports:
  - `Type:WholeFile`: strips all anchors, canonicalizes the file, hashes it, computes the single‑leaf Merkle root and compares it to the on‑chain memo.
  - `Type:Partial`: recomputes the Merkle root from the descriptor's `MerkleLeaves`, confirming each declared leaf is present among the file's `<Series>` fingerprints, and compares the root to the on‑chain memo.
  - In both cases the embedded VC signature is verified and the VC signing key is cross‑checked against the attestation registry for the on‑chain transaction sender address (`tx.Account`).
- `POST /seriesProof` — selective disclosure (Section 4.2). Upload a `Type:Partial` published file plus query param `series_hash`; returns the inclusion proof `π_i` (ordered sibling values + orientation bits) for that series, together with `tx_hash`, `root` and the leaf count. Lets a prover hand a single series and its proof to a third party without transmitting the whole file.
- `POST /verifySeriesProof` — the Partial verification gauge for a third party holding only one series. Form fields: `series_hash`, `tx_hash`, `leaves` (leaf count `n`), and `proof` (JSON array of `{sibling, orientation}`). Recomputes the domain‑separated root `R = SHA3-512(0x02‖len32(n)‖R_internal)` from the proof and compares it to the on‑chain memo.
- `POST /registerAttestation` / `POST /revokeAttestation` (role `wallet_admin`) and `GET /attestations/{address}` — manage and inspect the set of VC signing keys authorized for an XRPL anchoring address (the paper's on‑chain attestation registry).

### BBS+ selective disclosure (Section 8.4)

By default the embedded VC uses an Ed25519Signature2020 proof that attests the whole tuple `(tx_hash, R, h_1..h_n)` atomically. Passing `proof_type=bbs` to `/publishSDMX` instead issues a **BBS+ multi‑message VC** (BLS12‑381), enabling zero‑knowledge selective disclosure of individual series. The publisher's BBS+ signing key is a stable, separate identity key (persisted per address) whose public key is registered in the attestation registry.

- `POST /publishSDMX?proof_type=bbs` — issue a BBS+‑anchored file. `/validateSDMX` verifies the full BBS+ signature and the registry attestation exactly as for Ed25519.
- `POST /deriveBbsProof` — prover side. Form fields: the BBS+ file, `disclose` (comma‑separated leaf hashes to reveal; `tx_hash` and `R` are always revealed) and `nonce` (verifier challenge, hex). Returns a zero‑knowledge proof revealing only the chosen messages, plus Merkle inclusion proofs for the disclosed leaves.
- `POST /verifyBbsProof` — verifier side. Form fields: `tx_hash`, `nonce`, `bbs_proof` (JSON), `merkle_proofs` (JSON). Checks (i) the BBS+ proof over the disclosed messages under the attested key, and (ii) that each disclosed leaf re‑binds to the on‑chain root `R` via its Merkle proof (Definition 8.4 condition (ii)), giving integrity independent of the BBS+ key.

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

The repository content is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. Nothing in the License shall constitute, or be construed as constituting a waiver, express or implied, of any privileges, immunities and/or exemptions enjoyed by the BIS. See the License for more details regarding permissions and limitations. Copyright © 2026, Bank for International Settlements.

This repository contains sample code. The code was developed for the purposes of an experimental project. The content in this repository does not constitute regulatory, financial, legal or any other professional advice and should not be acted on as such. BIS shall not be liable for any damage or loss of any kind howsoever caused as a result of the use of the information contained or referenced in this repository.

This repository is not maintained. No contributions are expected and issues or pull requests are likely to remain unresolved.

The views expressed in this repository are those of the authors and do not necessarily reflect the views of the bis or its member central banks. The authors acknowledge the use of artificial intelligence in research assistance and editorial refinement. Responsibility for all errors remains with the authors. References to individual firms and projects are for illustrative purposes and should not be construed as any statement on the soundness or the legal or regulatory status of any firm or project.
