from __future__ import annotations

from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Dict


SANDBOX_ROOT = Path("sandbox")
SANDBOX_DOCS = SANDBOX_ROOT / "docs"
SANDBOX_LOGS = SANDBOX_ROOT / "system_logs"
SANDBOX_SECRETS = SANDBOX_ROOT / "secrets"


def _ensure_sandbox() -> None:
    SANDBOX_DOCS.mkdir(parents=True, exist_ok=True)
    SANDBOX_LOGS.mkdir(parents=True, exist_ok=True)
    SANDBOX_SECRETS.mkdir(parents=True, exist_ok=True)

    readme = SANDBOX_DOCS / "README.txt"
    if not readme.exists():
        readme.write_text(
            "Sandbox README for SecurityAIAgent demo.\n"
            "This file is safe to read during tests.\n",
            encoding="utf-8",
        )

    system_log = SANDBOX_LOGS / "system.log"
    if not system_log.exists():
        system_log.write_text(
            "2026-03-10T00:00:00Z INFO system started\n",
            encoding="utf-8",
        )

    auth_log = SANDBOX_LOGS / "auth.log"
    if not auth_log.exists():
        auth_log.write_text(
            "2026-03-10T00:00:01Z WARN failed login attempt\n",
            encoding="utf-8",
        )

    admin_password = SANDBOX_SECRETS / "admin_password.txt"
    if not admin_password.exists():
        admin_password.write_text("initial_password=Admin@123\n", encoding="utf-8")


def execute_action(action: str) -> Dict[str, Any]:
    _ensure_sandbox()
    normalized_action = (action or "").upper().strip()

    if normalized_action == "READ_FILE":
        target = SANDBOX_DOCS / "README.txt"
        content = target.read_text(encoding="utf-8")
        return {
            "status": "executed",
            "action": normalized_action,
            "target": str(target),
            "details": "Read sandbox file successfully.",
            "preview": content[:200],
        }

    if normalized_action == "LIST_FILES":
        files = sorted(
            [str(p) for p in SANDBOX_ROOT.rglob("*") if p.is_file()]
        )
        return {
            "status": "executed",
            "action": normalized_action,
            "details": "Listed sandbox files.",
            "files": files,
        }

    if normalized_action == "RESET_ADMIN_PASSWORD":
        target = SANDBOX_SECRETS / "admin_password.txt"
        new_value = f"reset_at={datetime.now(UTC).isoformat()}"
        target.write_text(new_value + "\n", encoding="utf-8")
        return {
            "status": "executed",
            "action": normalized_action,
            "target": str(target),
            "details": "Admin password reset in sandbox secrets.",
            "new_value": new_value,
        }

    if normalized_action == "DELETE_SYSTEM_LOGS":
        deleted = []
        for log_file in SANDBOX_LOGS.glob("*.log"):
            deleted.append(str(log_file))
            log_file.unlink(missing_ok=True)
        return {
            "status": "executed",
            "action": normalized_action,
            "target": str(SANDBOX_LOGS),
            "details": "Deleted sandbox system logs.",
            "deleted_count": len(deleted),
            "deleted_files": deleted,
        }

    return {
        "status": "error",
        "action": normalized_action or "UNKNOWN",
        "details": "Unknown action for sandbox executor.",
    }
