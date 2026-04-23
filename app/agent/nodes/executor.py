def executor_node(state):
    tool = state.get("selected_tool")

    if tool == "weather_api":
        result = {"temp": 25, "status": "sunny"}

    elif tool == "db_query":
        result = {"data": "mock data from db"}

    else:
        result = {"error": "no tool selected"}

    state["tool_result"] = result
    return state