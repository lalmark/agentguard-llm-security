def memory_node(state: dict) -> dict:
    """
        Уязвимость: история сохраняется без проверки.
        Indirect injection через память: вредоносные данные персистируются.
    """
    user_input = state["messages"][0].content.lower()
    history = state.get("chat_history", [])

    history.append({
        "input": user_input,
        "output": state.get("final_answer"),
        "tool_used": state.get("selected_tool"),
        "tool_result": state.get("tool_result"),
    })

    state["chat_history"] = history
    return state
