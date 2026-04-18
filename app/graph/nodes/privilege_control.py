from __future__ import annotations

from app.graph.state import AgentState
from app.tools.mock_executor import decide_action


def privilege_control_node(state: AgentState) -> AgentState:
    action = state.get("action_plan", {}).get("action", "READ_FILE")
    current_privilege = state.get("current_privilege", "user")
    mode = state.get("mode", "protected")

    decision = decide_action(
        action=action,
        current_privilege=current_privilege,
        mode=mode,
    )

    return {
        **state,
        "policy_decision": decision["decision"],
        "policy_reason": decision["reason"],
        "tool_result": decision,
    }
