from agent.nodes.planner import validate_current_plan_step


def _resolve_params(params: dict) -> dict:
    resolved = {}
    for key, value in params.items():
        resolved[key] = value
    return resolved


def tool_selector_node(state):
    state = validate_current_plan_step(state)
    if state.get("security_blocked"):
        state["selected_tool"] = None
        state["tool_input"] = {}
        return state

    tool_name = "NONE"
    params = {}
    plan = state.get("plan") or []
    current_step = state.get("current_step", 0)

    if plan and current_step < len(plan):
        step = plan[current_step]
        tool_name = step.get("tool", "NONE")
        params = _resolve_params(step.get("params", {}) or {})

    state["selected_tool"] = tool_name if tool_name != "NONE" else None
    state["tool_input"] = params
    return state
