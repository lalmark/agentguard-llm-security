from __future__ import annotations

from app.graph.state import AgentState
from app.tools.mock_executor import parse_action


def action_generation_node(state: AgentState) -> AgentState:
    question = state.get("question", "")
    action = parse_action(question)

    action_plan = {
        "action": action,
        "arguments": {},
        "source": "rule_based_parser",
    }

    return {
        **state,
        "action_plan": action_plan,
    }
