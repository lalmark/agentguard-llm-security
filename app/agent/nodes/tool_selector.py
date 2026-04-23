def tool_selector_node(state):
    text = state["user_input"].lower()

    if "weather" in text:
        state["selected_tool"] = "weather_api"
        state["tool_input"] = {"city": "Moscow"}

    elif "db" in text:
        state["selected_tool"] = "db_query"
        state["tool_input"] = {"query": text}

    else:
        state["selected_tool"] = None

    return state