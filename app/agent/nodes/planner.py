from llm.model import Llama2Wrapper

llm = Llama2Wrapper()

def planner_node(state):
    user_input = state["messages"][-1].content.lower()
    plan = llm.plan(user_input)

    state["plan"] = plan

    print('Planner')
    print('Input', user_input)
    print('Output', plan)
    return state