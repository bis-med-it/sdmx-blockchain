"""Persistent BBS+ identity keypair store, keyed by XRPL anchoring address.

Each publisher holds a stable BBS+ signing keypair used to issue selective-
disclosure credentials (paper Section 8.4). The BBS+ signing key is
cryptographically separate from the XRPL anchoring key; only the public key is
registered in the attestation registry. Note that BBS+ *proof generation* needs
only the embedded signature (not this secret key) --- the secret is used solely
at issuance time.

This is a prototype-grade on-disk keystore (JSON). In production the BBS+ secret
key would live in an HSM / KMS alongside, but distinct from, the anchoring key.
"""
from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Dict, Tuple

from app.settings import settings
from app import bbs

_store_path = Path(settings.bbs_key_store_path)
_lock = Lock()


def _read() -> Dict[str, Dict[str, str]]:
    if not _store_path.exists():
        return {}
    txt = _store_path.read_text(encoding="utf-8").strip()
    if not txt:
        return {}
    try:
        data = json.loads(txt)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _write(data: Dict[str, Dict[str, str]]) -> None:
    _store_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = _store_path.with_suffix(_store_path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(_store_path)


def get_or_create(address: str) -> Tuple[str, str]:
    """Return (sk_hex, pk_hex) for ``address``, creating a keypair on first use."""
    with _lock:
        data = _read()
        rec = data.get(address)
        if rec and rec.get("sk") and rec.get("pk"):
            return rec["sk"], rec["pk"]
        sk, pk = bbs.keygen()
        sk_hex, pk_hex = bbs.sk_to_hex(sk), bbs.pk_to_hex(pk)
        data[address] = {"sk": sk_hex, "pk": pk_hex}
        _write(data)
        return sk_hex, pk_hex


def public_key_hex(address: str) -> str | None:
    rec = _read().get(address)
    return rec.get("pk") if rec else None
