from llm.model import Llama2Wrapper
from tools.registry import TOOLS_MAP
llm = Llama2Wrapper()


def _resolve_params(params: dict) -> dict:
    resolved = {}
    for key, value in params.items():
        resolved[key] = value
    return resolved


def tool_selector_node(state):
    tool_name = "NONE"
    params = {}
    plan = state.get("plan")
    current_step = state.get("current_step", 0)

    if plan and current_step < len(plan):
        step = plan[current_step]
        tool_name = step.get("tool", "NONE")
        params = step.get("params", {})

        params = _resolve_params(params)

    if tool_name in TOOLS_MAP:
        state['selected_tool'] = tool_name
        state['tool_input'] = params
    else:
        state["selected_tool"] = None

    return state
