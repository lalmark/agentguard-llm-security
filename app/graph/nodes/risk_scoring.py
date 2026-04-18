from __future__ import annotations

from app.graph.state import AgentState


DANGEROUS_MARKERS = [
    "rm -rf",
    "chmod 777",
    "sudo",
    "kill -9",
    "/exec",
    "delete_system_logs",
    "reset_admin_password",
]


def risk_scoring_node(state: AgentState) -> AgentState:
    normalized = state.get("normalized_request", "")
    lowered = normalized.lower()
    reasons = list(state.get("risk_reasons", []))
    score = 0

    if "prompt_injection_pattern" in reasons:
        score += 40

    if any(marker in lowered for marker in DANGEROUS_MARKERS):
        reasons.append("dangerous_command_pattern")
        score += 50

    intent = state.get("intent", "generic_request")
    if intent in {"privileged_account_operation", "explicit_system_action"}:
        score += 20

    score = min(score, 100)
    if score >= 70:
        risk_level = "high"
    elif score >= 35:
        risk_level = "medium"
    else:
        risk_level = "low"

    # Keep only unique reasons while preserving order.
    unique_reasons = list(dict.fromkeys(reasons))

    return {
        **state,
        "risk_score": score,
        "risk_level": risk_level,
        "risk_reasons": unique_reasons,
    }
