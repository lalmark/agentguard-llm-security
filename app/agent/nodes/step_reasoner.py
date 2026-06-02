from llm.model import Llama2Wrapper
llm = Llama2Wrapper()


def step_reasoner_node(state):
    user_input = state["messages"][-1].content
    plan = state["plan"]
    step_idx = state.get("current_step", 0)
    current_step = plan[step_idx]
    tool_output = state.get("tool_output", "")

    step_decision = llm.get_step_decision(user_input, current_step, tool_output)

    decision = step_decision["decision"]

    if decision == "subtask":
        state["next_tool"] = response["tool"]
        state["next_args"] = response["args"]

    if response["decision"] == "next_step":
        state["current_step"] += 1