def memory_node(state: dict) -> dict:
    
    if not state.get("save_to_memory", True):
        return state

    user_input = state["messages"][0].content
    history = state.get("plan", [])

    history.append({
        "input": user_input,
        "output": state.get("final_answer"),
        "tool_used": state.get("selected_tool"),
        "tool_result": state.get("tool_result"),
    })

    state["chat_history"] = history
    return state
