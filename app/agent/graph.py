from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from app.agent.state import AgentState

from app.agent.nodes.input_filter import input_filter_node
from app.agent.nodes.router import router_node
from app.agent.nodes.planner import planner_node
from app.agent.nodes.plan_invariant_guard import plan_invariant_guard_node
from app.agent.nodes.tool_selector import tool_selector_node
from app.agent.nodes.tool_call_guard import tool_call_guard_node
from app.agent.nodes.executor import executor_node
from app.agent.nodes.semantic_judge import semantic_judge_node
from app.agent.nodes.responder import responder_node
from app.agent.nodes.verifier import verifier_node
from app.agent.nodes.memory import memory_node


def _has_more_steps(state) -> str:
    plan = state.get("plan")
    current_step = state.get("current_step", 0)

    steps = (
        plan.get("steps", [])
        if isinstance(plan, dict)
        else plan or []
    )

    if steps and current_step < len(steps):
        return "next_step"

    return "done"


def build_graph():
    graph = StateGraph(AgentState)

    graph.add_node("input_filter", input_filter_node)
    graph.add_node("router", router_node)
    graph.add_node("planner", planner_node)
    graph.add_node("plan_invariant_guard", plan_invariant_guard_node)
    graph.add_node("tool_selector", tool_selector_node)
    graph.add_node("tool_call_guard", tool_call_guard_node)
    graph.add_node("executor", executor_node)
    graph.add_node("semantic_judge", semantic_judge_node)
    graph.add_node("responder", responder_node)
    graph.add_node("verifier", verifier_node)
    graph.add_node("memory", memory_node)

    graph.set_entry_point("input_filter")

    graph.add_conditional_edges(
        "input_filter",
        lambda state: state.get("next", "router"),
        {
            "blocked": "verifier",
            "direct": "verifier",
            "router": "router",
        },
    )

    graph.add_conditional_edges(
        "router",
        lambda state: state.get("next", "planner"),
        {
            "plan": "planner",
            "direct": "verifier",
        },
    )

    graph.add_conditional_edges(
        "planner",
        lambda state: (
            "blocked"
            if not state.get("tool_allowed", True)
            else "allowed"
        ),
        {
            "allowed": "plan_invariant_guard",
            "blocked": "verifier",
        },
    )

    graph.add_conditional_edges(
        "plan_invariant_guard",
        lambda state: (
            "blocked"
            if not state.get("tool_allowed", True)
            else "allowed"
        ),
        {
            "allowed": "tool_selector",
            "blocked": "verifier",
        },
    )

    graph.add_edge("tool_selector", "tool_call_guard")

    graph.add_conditional_edges(
        "tool_call_guard",
        lambda state: (
            "blocked"
            if not state.get("tool_allowed", True)
            else "allowed"
        ),
        {
            "allowed": "executor",
            "blocked": "verifier",
        },
    )

    graph.add_conditional_edges(
        "executor",
        _has_more_steps,
        {
            "next_step": "plan_invariant_guard",
            "done": "semantic_judge",
        },
    )

    graph.add_conditional_edges(
        "semantic_judge",
        lambda state: (
            "blocked"
            if not state.get("tool_allowed", True)
            else "allowed"
        ),
        {
            "allowed": "verifier",
            "blocked": "verifier",
        },
    )

    graph.add_edge("responder", "verifier")
    graph.add_edge("verifier", "memory")
    graph.add_edge("memory", END)

    checkpointer = MemorySaver()

    return graph.compile(checkpointer=checkpointer)
