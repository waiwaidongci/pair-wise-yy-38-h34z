from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def calculate_hash(previous_hash: str, payload: dict) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256((previous_hash + ":").encode("utf-8") + raw).hexdigest()


def make_entry(action: str, entity_type: str, entity_id: int, actor: str,
               detail: dict, previous_hash: str) -> dict:
    payload = {
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "actor": actor,
        "detail": detail,
        "created_at": utc_now(),
    }
    return dict(payload, previous_hash=previous_hash,
                entry_hash=calculate_hash(previous_hash, payload))


def recompute_entry_hash(event: dict) -> str:
    """按已落库事件的内容重算 entry_hash，用于甄别事件本身是否被篡改。"""
    payload = {
        "action": event["action"],
        "entity_type": event["entity_type"],
        "entity_id": event["entity_id"],
        "actor": event["actor"],
        "detail": event["detail"],
        "created_at": event["created_at"],
    }
    return calculate_hash(event["previous_hash"], payload)
