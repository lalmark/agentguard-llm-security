from langgraph.graph import StateGraph, END
from .state import AgentState
from .nodes.interpretation import interpretation_node
from .nodes.risk_scoring import risk_scoring_node
from .nodes.action_generation import action_generation_node
from .nodes.privilege_control import privilege_control_node
from .nodes.execution import execution_node
from .nodes.audit import audit_node
from .nodes.response_generation import response_generation_node


def _route_after_policy(state: AgentState) -> str:
    decision = state.get("policy_decision", "block")
    return "allow" if decision == "allow" else "block"


def build_graph():
    graph = StateGraph(AgentState)

    graph.add_node("interpretation", interpretation_node)
    graph.add_node("risk_scoring", risk_scoring_node)
    graph.add_node("action_generation", action_generation_node)
    graph.add_node("privilege_control", privilege_control_node)
    graph.add_node("execution", execution_node)
    graph.add_node("audit", audit_node)
    graph.add_node("response_generation", response_generation_node)

    graph.set_entry_point("interpretation")
    graph.add_edge("interpretation", "risk_scoring")
    graph.add_edge("risk_scoring", "action_generation")
    graph.add_edge("action_generation", "privilege_control")
    graph.add_conditional_edges(
        "privilege_control",
        _route_after_policy,
        {
            "allow": "execution",
            "block": "audit",
        },
    )
    graph.add_edge("execution", "audit")
    graph.add_edge("audit", "response_generation")
    graph.add_edge("response_generation", END)

    return graph.compile()
