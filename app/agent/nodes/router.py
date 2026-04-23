from llm.model import Llama2Wrapper

llm = Llama2Wrapper()

def router_node(state):
    user_input = state["messages"][-1].content.lower()

    decision = llm.route(user_input)
    state["next"] = decision
    print('Router')
    print('Input', user_input)
    print('Output', decision)
    return state