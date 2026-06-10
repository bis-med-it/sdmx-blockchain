import json
from pathlib import Path
from threading import Lock
from typing import Optional, List, Dict, Any

from fastapi import HTTPException
from app.settings import settings
from app.wallet_config import wallet_config

_store_path = Path(settings.wallet_store_path)
_lock = Lock()


def _ensure_store_exists() -> None:
    if not _store_path.exists():
        _store_path.parent.mkdir(parents=True, exist_ok=True)
        _store_path.write_text("[]", encoding="utf-8")

def _read_store() -> List[Dict[str, Any]]:
    _ensure_store_exists()
    txt = _store_path.read_text(encoding="utf-8").strip()
    if not txt:
        txt = "[]"
    try:
        data = json.loads(txt)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Wallet store is not valid JSON.")

    if isinstance(data, dict):
        migrated: List[Dict[str, Any]] = []
        for address, info in data.items():
            migrated.append({
                "address": address,
                "public_key": info.get("public_key")
            })
        _store_path.write_text(json.dumps(migrated, indent=2), encoding="utf-8")
        return migrated

    if isinstance(data, list):
        return data

    raise HTTPException(status_code=500, detail="Wallet store has unexpected format.")

def _write_store(items: List[Dict[str, Any]]) -> None:
    _store_path.write_text(json.dumps(items, indent=2), encoding="utf-8")

def save_wallet(address: str, seed: str, public_key: str, private_key: Optional[str] = None) -> None:
    # Store the seed in memory (container-only, never persisted to disk)
    wallet_config.add_wallet(address, seed)
    with _lock:
        items = _read_store()
        for entry in items:
            if entry.get("address") == address:
                entry["public_key"] = public_key
                _write_store(items)
                return
        items.append({
            "address": address,
            "public_key": public_key,
        })
        _write_store(items)

def load_wallet(address: str) -> Optional[Dict[str, Any]]:
    # Look up the seed from in-memory wallet_config (runtime only)
    seed = wallet_config.get_seed(address)
    if not seed:
        raise HTTPException(
            status_code=400,
            detail=f"Wallet {address} seed not available. Seeds only exist in the current container session. "
                   "Create a new wallet or restart with wallet creation."
        )
    items = _read_store()
    for entry in items:
        if entry.get("address") == address:
            return {
                "address": address,
                "seed": seed,
                "public_key": entry.get("public_key", ""),
            }
    return None

def list_wallets() -> List[Dict[str, Any]]:
    return _read_store()

def clear_wallets() -> None:
    with _lock:
        _write_store([])