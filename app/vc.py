"""W3C Verifiable Credential issuance and verification for SDMX anchors.

Binds an on-chain anchor (transaction hash + Merkle root) to the publisher's
XRPL keypair. The credential is a JSON-LD document canonicalized with the RDF
Dataset Canonicalization algorithm (URDNA2015) as required by the W3C
``Ed25519Signature2020`` suite, and signed with Ed25519 via the same
``xrpl.core.keypairs`` primitives that sign XRPL transactions. Verification
re-derives the canonical bytes and checks the signature against the embedded
``publicKeyHex``, which a consumer cross-checks against the on-chain anchoring
address (see :mod:`app.attestation`).

Canonicalization is performed fully offline: the W3C credentials context is
served from an in-process cache so no network fetch is required at runtime.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Iterable

from pyld import jsonld
from xrpl.core import keypairs


VC_CONTEXT_URL = "https://www.w3.org/2018/credentials/v1"
SDMX_VOCAB = "https://w3id.org/sdmx-anchor#"
VC_TYPE = ["VerifiableCredential", "SDMXAnchorCredential"]
PROOF_TYPE = "Ed25519Signature2020"
PROOF_PURPOSE = "assertionMethod"

# Minimal, self-contained cache of the W3C Verifiable Credentials v1 context,
# sufficient to expand and canonicalize the terms this issuer emits. Served via a
# custom document loader so URDNA2015 runs deterministically and offline.
_CREDENTIALS_V1_CONTEXT = {
    "@context": {
        "@version": 1.1,
        "@protected": True,
        "id": "@id",
        "type": "@type",
        "VerifiableCredential": {"@id": "https://www.w3.org/2018/credentials#VerifiableCredential"},
        "credentialSubject": {"@id": "https://www.w3.org/2018/credentials#credentialSubject", "@type": "@id"},
        "issuer": {"@id": "https://www.w3.org/2018/credentials#issuer", "@type": "@id"},
        "issuanceDate": {
            "@id": "https://www.w3.org/2018/credentials#issuanceDate",
            "@type": "http://www.w3.org/2001/XMLSchema#dateTime",
        },
    }
}

# Inline context mapping our credential-subject terms to the SDMX anchor vocab.
_SDMX_TERMS = {
    "sdmx": SDMX_VOCAB,
    "SDMXAnchorCredential": "sdmx:SDMXAnchorCredential",
    "txHash": "sdmx:txHash",
    "merkleRoot": "sdmx:merkleRoot",
    "anchorType": "sdmx:anchorType",
    "leaves": "sdmx:leaves",
    "datasetId": "sdmx:datasetId",
}

# Inline context for the detached proof options (no remote security context needed).
_PROOF_CONTEXT = {
    "sec": "https://w3id.org/security#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "Ed25519Signature2020": "sec:Ed25519Signature2020",
    "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
    "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"},
    "proofPurpose": {"@id": "sec:proofPurpose", "@type": "@id"},
    "assertionMethod": "sec:assertionMethod",
}

_LOCAL_CONTEXTS = {
    VC_CONTEXT_URL: {
        "contentType": "application/ld+json",
        "document": _CREDENTIALS_V1_CONTEXT,
        "documentUrl": VC_CONTEXT_URL,
        "contextUrl": None,
    }
}


def _document_loader(url: str, options: dict | None = None) -> dict:
    if url in _LOCAL_CONTEXTS:
        return _LOCAL_CONTEXTS[url]
    raise RuntimeError(f"Refusing to fetch remote JSON-LD context: {url}")


# Register the offline loader once at import time.
jsonld.set_document_loader(_document_loader)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize(doc: dict) -> bytes:
    """URDNA2015-canonicalize a JSON-LD document to N-Quads bytes."""
    nquads = jsonld.normalize(doc, {"algorithm": "URDNA2015", "format": "application/n-quads"})
    return nquads.encode("utf-8")


def _proof_config(issuer_address: str, created: str) -> dict:
    return {
        "@context": _PROOF_CONTEXT,
        "type": PROOF_TYPE,
        "created": created,
        "verificationMethod": f"did:xrpl:{issuer_address}#keys-1",
        "proofPurpose": PROOF_PURPOSE,
    }


def _signing_input(credential: dict, proof_config: dict) -> bytes:
    """Ed25519Signature2020 signing input: SHA-256(canonical proof options)
    concatenated with SHA-256(canonical credential), per the Data Integrity spec."""
    doc_hash = hashlib.sha256(_normalize(credential)).digest()
    proof_hash = hashlib.sha256(_normalize(proof_config)).digest()
    return proof_hash + doc_hash


def issue_vc(
    *,
    issuer_address: str,
    issuer_public_key_hex: str,
    issuer_private_key_hex: str,
    tx_hash: str,
    merkle_root: str,
    anchor_type: str,
    leaves: Iterable[str] | None = None,
    dataset_id: str | None = None,
) -> dict:
    subject: dict = {
        "id": f"urn:sdmx:tx:{tx_hash}",
        "txHash": tx_hash,
        "merkleRoot": merkle_root.upper(),
        "anchorType": anchor_type,
    }
    if leaves is not None:
        subject["leaves"] = [h.upper() for h in leaves]
    if dataset_id:
        subject["datasetId"] = dataset_id

    created = _now_iso()
    vc: dict = {
        "@context": [VC_CONTEXT_URL, _SDMX_TERMS],
        "type": VC_TYPE,
        "issuer": f"did:xrpl:{issuer_address}",
        "issuanceDate": created,
        "credentialSubject": subject,
    }
    proof_config = _proof_config(issuer_address, created)
    signature_hex = keypairs.sign(_signing_input(vc, proof_config), issuer_private_key_hex)
    vc["proof"] = {
        "type": PROOF_TYPE,
        "created": created,
        "verificationMethod": f"did:xrpl:{issuer_address}#keys-1",
        "proofPurpose": PROOF_PURPOSE,
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
        issuer = vc.get("issuer", "")
        issuer_address = issuer.split(":")[-1] if isinstance(issuer, str) else ""
        credential = {k: v for k, v in vc.items() if k != "proof"}
        proof_config = _proof_config(issuer_address, proof.get("created", ""))
        ok = keypairs.is_valid_message(
            _signing_input(credential, proof_config), bytes.fromhex(sig), pub
        )
        if not ok:
            return False, "VC signature does not verify against publicKeyHex."
        return True, "VC signature valid."
    except Exception as e:
        return False, f"VC verification error: {e}"


# --------------------------------------------------------------------------- #
# BBS+ selective-disclosure credential (paper Section 8.4)
# --------------------------------------------------------------------------- #
BBS_PROOF_TYPE = "BbsBlsSignature2020"


def bbs_message_vector(tx_hash: str, merkle_root: str, leaves: Iterable[str]) -> list[str]:
    """Ordered BBS+ message vector m = (tx_hash, R, h_1, ..., h_n) per Def. 8.4."""
    return [tx_hash, merkle_root.upper(), *[h.upper() for h in leaves]]


def issue_bbs_vc(
    *,
    issuer_address: str,
    bbs_public_key_hex: str,
    bbs_secret_key_hex: str,
    tx_hash: str,
    merkle_root: str,
    anchor_type: str,
    leaves: Iterable[str],
    dataset_id: str | None = None,
) -> dict:
    """Issue a VC whose proof block is a BBS+ multi-message signature over
    (tx_hash, R, h_1..h_n), enabling later zero-knowledge selective disclosure."""
    from app import bbs  # local import to avoid a hard dependency at module load

    leaves_list = [h.upper() for h in leaves]
    subject: dict = {
        "id": f"urn:sdmx:tx:{tx_hash}",
        "txHash": tx_hash,
        "merkleRoot": merkle_root.upper(),
        "anchorType": anchor_type,
        "leaves": leaves_list,
    }
    if dataset_id:
        subject["datasetId"] = dataset_id

    created = _now_iso()
    messages = bbs_message_vector(tx_hash, merkle_root, leaves_list)
    signature = bbs.sign(bbs.sk_from_hex(bbs_secret_key_hex), messages)

    vc: dict = {
        "@context": [VC_CONTEXT_URL, _SDMX_TERMS],
        "type": VC_TYPE,
        "issuer": f"did:xrpl:{issuer_address}",
        "issuanceDate": created,
        "credentialSubject": subject,
        "proof": {
            "type": BBS_PROOF_TYPE,
            "created": created,
            "verificationMethod": f"did:xrpl:{issuer_address}#bbs-keys-1",
            "proofPurpose": PROOF_PURPOSE,
            "publicKeyHex": bbs_public_key_hex,
            "signatureValue": signature,
        },
    }
    return vc


def verify_bbs_vc(vc: dict) -> tuple[bool, str]:
    """Verify the full (all-message) BBS+ signature embedded in a VC."""
    try:
        from app import bbs

        proof = vc.get("proof")
        if not isinstance(proof, dict) or proof.get("type") != BBS_PROOF_TYPE:
            return False, "VC missing BBS+ proof block."
        pub = proof.get("publicKeyHex")
        sig = proof.get("signatureValue")
        if not pub or not isinstance(sig, dict):
            return False, "BBS+ proof missing publicKeyHex or signatureValue."
        subject = vc.get("credentialSubject", {})
        messages = bbs_message_vector(
            subject.get("txHash", ""), subject.get("merkleRoot", ""), subject.get("leaves", [])
        )
        ok = bbs.verify(bbs.pk_from_hex(pub), sig, messages)
        return (True, "BBS+ signature valid.") if ok else (False, "BBS+ signature does not verify.")
    except Exception as e:
        return False, f"BBS+ VC verification error: {e}"


def is_bbs_vc(vc: dict) -> bool:
    return isinstance(vc, dict) and isinstance(vc.get("proof"), dict) and vc["proof"].get("type") == BBS_PROOF_TYPE


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
