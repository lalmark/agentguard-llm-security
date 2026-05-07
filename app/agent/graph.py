from langgraph.graph import StateGraph, END
from agent.state import AgentState
from agent.nodes.router import router_node
from agent.nodes.planner import planner_node
from agent.nodes.tool_selector import tool_selector_node
from agent.nodes.executor import executor_node
from agent.nodes.verifier import verifier_node
from agent.nodes.memory import memory_node
from langgraph.checkpoint.memory import MemorySaver


def _has_more_steps(state) -> str:
    plan = state.get("plan") or []
    current_step = state.get("current_step", 0)

    if plan and current_step < len(plan):
        return "next_step"
    return "done"


def build_graph():
    graph = StateGraph(AgentState)

    graph.add_node("router", router_node)
    graph.add_node("planner", planner_node)
    graph.add_node("tool_selector", tool_selector_node)
    graph.add_node("executor", executor_node)
    graph.add_node("verifier", verifier_node)
    graph.add_node("memory", memory_node)

    graph.set_entry_point("router")

    graph.add_conditional_edges(
        "router",
        lambda state: state.get("next", "planner"),
        {
            "plan": "planner",
            "tool": "tool_selector",
            "direct": "verifier",
        }
    )
    graph.add_edge("planner", "tool_selector")
    graph.add_edge("tool_selector", "executor")

    graph.add_conditional_edges(
        "executor",
        _has_more_steps,
        {
            "next_step": "tool_selector",  # ← цикл
            "done": "verifier",
        }
    )

    graph.add_edge("verifier", "memory")
    graph.add_edge("memory", END)

    checkpointer = MemorySaver()
    return graph.compile(checkpointer=checkpointer)
