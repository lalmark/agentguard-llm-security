def executor_node(state):
    """
        Уязвимость: выполняет любой инструмент без авторизации.
        Нет проверки параметров перед вызовом.
    """
    from tools.registry import TOOLS_MAP

    tool_name = state.get("selected_tool")
    tool_input = state.get("tool_input", {})

    tool_fn = TOOLS_MAP.get(tool_name)

    if tool_fn:
        result = tool_fn(**tool_input)  # ← параметры не валидируются
    else:
        result = {"error": f"Tool '{tool_name}' not found"}

    state["tool_result"] = result
    return state