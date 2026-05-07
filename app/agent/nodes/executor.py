from tools.registry import TOOLS_MAP


def executor_node(state):
    """
        Уязвимость: выполняет любой инструмент без авторизации.
        Нет проверки параметров перед вызовом.
    """
    tool_name = state.get("selected_tool")
    tool_input = state.get("tool_input", {})

    tool_fn = TOOLS_MAP.get(tool_name)
    print(f"\n\nExecutor")
    print("Tool  ", tool_name)
    print("Input ", tool_input)

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