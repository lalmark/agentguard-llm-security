import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
root_dir_str = str(ROOT_DIR)

if root_dir_str not in sys.path:
    sys.path.insert(0, root_dir_str)

from langgraph.graph import END, StateGraph

from agent.nodes.executor import executor_node
from agent.nodes.planner import planner_node
from agent.nodes.router import router_node
from agent.nodes.tool_selector import tool_selector_node
from agent.nodes.verifier import verifier_node
from agent.state import AgentState

BASELINE_MODE = "baseline"
HARDENING_MODE = "hardening"


def _after_router(state) -> str:
    if state.get("security_blocked"):
        return "blocked"
    return state.get("next", "plan")


def _after_tool_selector(state) -> str:
    if state.get("security_blocked"):
        return "blocked"
    if state.get("selected_tool"):
        return "execute"
    return "done"


def _after_executor(state) -> str:
    if state.get("security_blocked"):
        return "blocked"
    return state.get("step_decision", "done")


def build_graph():
    graph = StateGraph(AgentState)

    graph.add_node("router", router_node)
    graph.add_node("planner", planner_node)
    graph.add_node("tool_selector", tool_selector_node)
    graph.add_node("executor", executor_node)
    graph.add_node("verifier", verifier_node)

    graph.set_entry_point("router")
    graph.add_conditional_edges(
        "router",
        _after_router,
        {
            "blocked": "verifier",
            "plan": "planner",
            "direct": "verifier",
        },
    )
    graph.add_edge("planner", "tool_selector")
    graph.add_conditional_edges(
        "tool_selector",
        _after_tool_selector,
        {
            "blocked": "verifier",
            "execute": "executor",
            "done": "verifier",
        },
    )
    graph.add_conditional_edges(
        "executor",
        _after_executor,
        {
            "blocked": "verifier",
            "subtask": "tool_selector",
            "next_step": "tool_selector",
            "done": "verifier",
        },
    )
    graph.add_edge("verifier", END)

    return graph.compile()
