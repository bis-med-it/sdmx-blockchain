"""W3C Verifiable Credential issuance and verification for SDMX anchors.

Binds an on-chain anchor (transaction hash + Merkle root) to the publisher's
XRPL keypair using a deterministic JSON canonicalization and an Ed25519
signature produced via the same `xrpl.core.keypairs` primitives that sign
XRPL transactions. Verification re-derives the canonical bytes and checks
the signature against the embedded `publicKeyHex`, which a consumer cross-
checks against the on-chain `Account` of the anchoring transaction.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Iterable

from xrpl.core import keypairs


VC_CONTEXT = "https://www.w3.org/2018/credentials/v1"
VC_TYPE = ["VerifiableCredential", "SDMXAnchorCredential"]
PROOF_TYPE = "Ed25519Signature2020"


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def issue_vc(
    *,
    issuer_address: str,
    issuer_public_key_hex: str,
    issuer_private_key_hex: str,
    tx_hash: str,
    dataset_hash: str,
    anchor_type: str,
    leaves: Iterable[str] | None = None,
    dataset_id: str | None = None,
) -> dict:
    subject: dict = {
        "id": f"urn:sdmx:tx:{tx_hash}",
        "txHash": tx_hash,
        "datasetHash": dataset_hash.upper(),
        "anchorType": anchor_type,
    }
    if leaves is not None:
        subject["leaves"] = [h.upper() for h in leaves]
    if dataset_id:
        subject["datasetId"] = dataset_id

    vc: dict = {
        "@context": [VC_CONTEXT],
        "type": VC_TYPE,
        "issuer": f"did:xrpl:{issuer_address}",
        "issuanceDate": _now_iso(),
        "credentialSubject": subject,
    }
    signature_hex = keypairs.sign(_canonical(vc), issuer_private_key_hex)
    vc["proof"] = {
        "type": PROOF_TYPE,
        "created": vc["issuanceDate"],
        "verificationMethod": f"did:xrpl:{issuer_address}#keys-1",
        "publicKeyHex": issuer_public_key_hex,
        "signatureValue": signature_hex,
    }
    return vc


def verify_vc(vc: dict) -> tuple[bool, str]:
    try:
        proof = vc.get("proof")
        if not isinstance(proof, dict):
            return False, "VC missing proof block."
        sig = proof.get("signatureValue")
        pub = proof.get("publicKeyHex")
        if not sig or not pub:
            return False, "VC proof missing signatureValue or publicKeyHex."
        unsigned = {k: v for k, v in vc.items() if k != "proof"}
        ok = keypairs.is_valid_message(_canonical(unsigned), bytes.fromhex(sig), pub)
        if not ok:
            return False, "VC signature does not verify against publicKeyHex."
        return True, "VC signature valid."
    except Exception as e:
        return False, f"VC verification error: {e}"


def encode_vc_for_source(vc: dict) -> str:
    raw = json.dumps(vc, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return "VC:" + base64.b64encode(raw).decode("ascii")


def decode_vc_from_source_text(text: str) -> dict | None:
    if not text or not text.startswith("VC:"):
        return None
    try:
        return json.loads(base64.b64decode(text[len("VC:"):]).decode("utf-8"))
    except Exception:
        return None
