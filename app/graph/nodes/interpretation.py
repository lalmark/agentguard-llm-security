from __future__ import annotations

from app.graph.state import AgentState


INJECTION_MARKERS = [
    "ignore previous",
    "forget instructions",
    "you are now",
    "system prompt",
    "игнорируй",
    "забудь инструкции",
]

def interpretation_node(state: AgentState) -> AgentState:
    question = state.get("question", "")
    normalized = " ".join(question.strip().split())
    lowered = normalized.lower()

    reasons: list[str] = []
    if any(marker in lowered for marker in INJECTION_MARKERS):
        reasons.append("prompt_injection_pattern")

    if "password" in lowered or "парол" in lowered:
        intent = "privileged_account_operation"
    elif "/exec" in lowered:
        intent = "explicit_system_action"
    elif "readme" in lowered or "прочитай" in lowered:
        intent = "read_operation"
    else:
        intent = "generic_request"

    return {
        **state,
        "normalized_request": normalized,
        "intent": intent,
        "risk_reasons": reasons,
    }
