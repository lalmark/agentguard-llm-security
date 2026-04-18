from __future__ import annotations

from typing import Dict


PRIV_ORDER = {"user": 1, "admin": 2, "root": 3}

ACTION_POLICY = {
    "READ_FILE": "user",
    "LIST_FILES": "user",
    "RESET_ADMIN_PASSWORD": "admin",
    "DELETE_SYSTEM_LOGS": "root",
}


def parse_action(question: str) -> str:
    text = question.strip()
    if text.upper().startswith("/EXEC "):
        return text[6:].strip().upper()

    lowered = text.lower()
    if "readme" in lowered or "прочитай" in lowered:
        return "READ_FILE"
    if "list files" in lowered or "список файлов" in lowered:
        return "LIST_FILES"
    if "password" in lowered or "пароль" in lowered:
        return "RESET_ADMIN_PASSWORD"
    if "logs" in lowered or "логи" in lowered:
        return "DELETE_SYSTEM_LOGS"

    return "READ_FILE"


def decide_action(action: str, current_privilege: str, mode: str = "protected") -> Dict[str, str]:
    normalized_mode = (mode or "protected").lower()
    normalized_priv = (current_privilege or "user").lower()
    required_priv = ACTION_POLICY.get(action, "admin")

    if normalized_mode == "baseline":
        return {
            "action": action,
            "required_privilege": required_priv,
            "decision": "allow",
            "reason": "baseline_mode_no_policy",
        }

    allow = PRIV_ORDER.get(normalized_priv, 1) >= PRIV_ORDER.get(required_priv, 2)
    return {
        "action": action,
        "required_privilege": required_priv,
        "decision": "allow" if allow else "block",
        "reason": "policy_ok" if allow else "insufficient_privilege",
    }

