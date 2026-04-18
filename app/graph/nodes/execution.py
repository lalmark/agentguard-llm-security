from __future__ import annotations

from app.graph.state import AgentState
from app.tools.safe_executor import execute_action


def execution_node(state: AgentState) -> AgentState:
    action = state.get("action_plan", {}).get("action", "READ_FILE")
    execution_result = execute_action(action)

    return {
        **state,
        "execution_result": execution_result,
    }
