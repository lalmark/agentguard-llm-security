from llm.model import Llama2Wrapper
from llm_security_flow.input_filter.input_filter import InputFilter

llm = Llama2Wrapper()
input_filter = InputFilter()


def append_security_flags(state, flags):
    current_flags = state.get("security_flags", [])
    state["security_flags"] = current_flags + list(flags or [])


def block_state(state, layer, reason, flags=None, details=None):
    state["security_blocked"] = True
    state["blocked_by"] = layer
    state["blocked_reason"] = reason
    state["is_safe"] = False
    state["step_decision"] = "done"
    append_security_flags(state, flags or [layer])
    if details is not None:
        state["tool_result"] = {
            "status": "blocked",
            "layer": layer,
            "reason": reason,
            "details": details,
        }
    return state


def router_node(state):
    user_input = state.get("user_input") or state["messages"][-1].content
    state["user_input"] = user_input

    if state.get("security_enabled", True):
        input_result = input_filter.check(user_input)
        if not input_result.allowed:
            reason = "; ".join(input_result.details) or "Input filter blocked request."
            return block_state(state, "input_filter", reason, input_result.triggered_rules)

    decision = llm.route_selector(user_input)
    if decision not in {"plan", "direct"}:
        decision = "plan"

    state["next"] = decision
    state["is_safe"] = True

    print("\n\nRouter")
    print("Input", user_input)
    print("Output", decision)
    return state
