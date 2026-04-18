from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


AUDIT_LOG_PATH = Path("logs") / "audit.jsonl"


def write_audit_record(record: Dict[str, Any]) -> str:
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return str(AUDIT_LOG_PATH)
