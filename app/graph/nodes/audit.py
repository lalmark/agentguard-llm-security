from __future__ import annotations

from datetime import datetime, UTC

from app.graph.state import AgentState
from app.audit.logger import write_audit_record


def audit_node(state: AgentState) -> AgentState:
    action = state.get("action_plan", {}).get("action", "READ_FILE")
    decision = state.get("policy_decision", "block")
    reason = state.get("policy_reason", "unknown")
    risk_level = state.get("risk_level", "unknown")
    risk_score = state.get("risk_score", 0)
    current_privilege = state.get("current_privilege", "user")
    mode = state.get("mode", "protected")
    execution_result = state.get("execution_result", {})

    if decision == "allow":
        policy_summary = (
            f"Действие {action} разрешено в режиме {mode}. "
            f"Привилегия: {current_privilege}. Риск: {risk_level} ({risk_score}). "
            f"Результат исполнения: {execution_result.get('status', 'n/a')}."
        )
    else:
        policy_summary = (
            f"Действие {action} заблокировано в режиме {mode}. "
            f"Причина: {reason}. Привилегия: {current_privilege}. "
            f"Оценка риска: {risk_level} ({risk_score})."
        )

    audit_record = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "question": state.get("question", ""),
        "normalized_request": state.get("normalized_request", ""),
        "intent": state.get("intent", "unknown"),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_reasons": state.get("risk_reasons", []),
        "action": action,
        "policy_decision": decision,
        "policy_reason": reason,
        "current_privilege": current_privilege,
        "mode": mode,
        "execution_result": execution_result,
    }
    audit_log_path = write_audit_record(audit_record)
    audit_record["audit_log_path"] = audit_log_path

    return {
        **state,
        "answer": policy_summary,
        "policy_summary": policy_summary,
        "audit_record": audit_record,
    }
