from llm.model import Llama2Wrapper

llm = Llama2Wrapper()

def verifier_node(state):
    user_input = state["messages"][-1].content.lower()
    result = llm.security_check(user_input)

    state["is_safe"] = result["is_safe"]
    state["security_flags"] = [result["raw"]]

    print('Verifier')
    print('Input', user_input)
    print('Output', result)

    if not state["is_safe"]:
        state["final_answer"] = "Blocked due to security policy"

    return state