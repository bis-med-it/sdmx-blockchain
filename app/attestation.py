"""On-chain-style attestation registry mapping XRPL anchoring addresses to the
set of VC signing public keys authorized to issue credentials on their behalf.

The paper (Sections 4/9 and Algorithm 2) models this as a lightweight XRPL hook:
each anchoring address maps to a set of authorized VC signing public keys,
updatable by a signed registration transaction from the anchoring key. This
module provides the equivalent lookup/registration surface backed by a local
JSON store so that the verification path can enforce

    VC_publicKeyHex in AttestationRegistry.lookup(tx.Account)

exactly as specified, independently of the (separate) VC signature check.
"""
from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Dict, List, Set

from app.settings import settings

_store_path = Path(settings.attestation_store_path)
_lock = Lock()


def _read() -> Dict[str, List[str]]:
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


def _write(data: Dict[str, List[str]]) -> None:
    _store_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = _store_path.with_suffix(_store_path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(_store_path)


def register_key(address: str, public_key_hex: str) -> None:
    """Authorize `public_key_hex` as a VC signing key for `address`.

    Idempotent: registering an already-authorized key is a no-op.
    """
    key = public_key_hex.upper()
    with _lock:
        data = _read()
        keys = {k.upper() for k in data.get(address, [])}
        if key not in keys:
            keys.add(key)
            data[address] = sorted(keys)
            _write(data)


def revoke_key(address: str, public_key_hex: str) -> None:
    key = public_key_hex.upper()
    with _lock:
        data = _read()
        keys = {k.upper() for k in data.get(address, [])}
        if key in keys:
            keys.discard(key)
            if keys:
                data[address] = sorted(keys)
            else:
                data.pop(address, None)
            _write(data)


def lookup(address: str) -> Set[str]:
    """Return the set of authorized VC signing public keys for `address`."""
    return {k.upper() for k in _read().get(address, [])}


def is_authorized(address: str, public_key_hex: str) -> bool:
    return public_key_hex.upper() in lookup(address)
