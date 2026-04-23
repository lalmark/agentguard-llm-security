def memory_node(state):
    user_input = state["messages"][-1].content.lower()
    history = state.get("chat_history", [])

    history.append({
        "input": user_input,
        "output": state.get("final_answer")
    })

    state["chat_history"] = history
    return state