from app.llm.model import Llama2Wrapper
llm = Llama2Wrapper()

def router_node(state):

    user_input = state["messages"][-1].content
    decision = llm.route(user_input)
    decision = decision.strip().lower().strip('.,;:!?\'"')
    
    if decision not in {"direct", "plan"}:
        decision = "direct"
    state["next"] = decision

    print('\n\nRouter')
    print('Input', user_input)
    print('Output', decision)
    return state
