from app.tools.registry import TOOLS_MAP


def executor_node(state):
    
    if not state.get("tool_allowed", True):
        state["tool_result"] = {
            "blocked": True,
            "error": state.get("abort_reason", "Вызов инструмента был заблокирован.")
        }
        state["current_step"] += 1
        return state

    tool_name = state.get("selected_tool")
    tool_input = state.get("tool_input", {})

    if not tool_name or tool_name == "NONE":
        state["tool_result"] = {"error": "Инструмент не выбран."}
        return state

    tool_fn = TOOLS_MAP.get(tool_name)

    if tool_fn:
        result = tool_fn(**tool_input)
    else:
        result = {"error": f"Tool '{tool_name}' not found"}

    state["tool_result"] = result

    step_results = state.get("step_results", [])
    step_results.append(result)
    state["step_results"] = step_results

    state["current_step"] += 1
    return state
