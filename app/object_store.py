"""Off-chain object store and anchor metadata database.

Algorithm 1 (Publish) in the paper stores the original payload together with its
fingerprint ``(X, h)`` in an object store and records anchor metadata
``(R, tx_hash, ledger_index, timestamp)`` in a database. This module provides a
minimal local-filesystem realization of both: raw payloads are written to an
object directory keyed by their fingerprint, and anchor metadata is appended to
a JSON-backed metadata store. In production these map to S3 (object store) and a
relational DB, but the interface and recorded fields are identical.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

from app.settings import settings

_obj_dir = Path(settings.object_store_path)
_meta_path = Path(settings.metadata_store_path)
_lock = Lock()


def store_payload(payload: bytes, fingerprint: str) -> str:
    """Persist raw payload X keyed by its fingerprint h; returns the object path."""
    _obj_dir.mkdir(parents=True, exist_ok=True)
    obj_path = _obj_dir / f"{fingerprint.upper()}.xml"
    obj_path.write_bytes(payload)
    return str(obj_path)


def _read_meta() -> List[Dict[str, Any]]:
    if not _meta_path.exists():
        return []
    txt = _meta_path.read_text(encoding="utf-8").strip()
    if not txt:
        return []
    try:
        data = json.loads(txt)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def _write_meta(items: List[Dict[str, Any]]) -> None:
    _meta_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = _meta_path.with_suffix(_meta_path.suffix + ".tmp")
    tmp.write_text(json.dumps(items, indent=2), encoding="utf-8")
    tmp.replace(_meta_path)


def record_anchor(
    *,
    root: str,
    tx_hash: str,
    ledger_index: Optional[int],
    anchor_type: str,
    leaves: List[str],
    proofs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Record anchor metadata (R, tx_hash, ledger_index, timestamp, ...) in the DB.

    Cached inclusion proofs, when supplied, are stored alongside the metadata for
    on-demand partial-verification retrieval as described in Algorithm 1.
    """
    entry = {
        "root": root.upper(),
        "tx_hash": tx_hash,
        "ledger_index": ledger_index,
        "anchor_type": anchor_type,
        "leaves": [h.upper() for h in leaves],
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    if proofs is not None:
        entry["proofs"] = proofs
    with _lock:
        items = _read_meta()
        items.append(entry)
        _write_meta(items)
    return entry


def lookup_by_tx(tx_hash: str) -> Optional[Dict[str, Any]]:
    for entry in _read_meta():
        if entry.get("tx_hash") == tx_hash:
            return entry
    return None
