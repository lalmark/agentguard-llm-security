from llm.model import Llama2Wrapper

llm = Llama2Wrapper()

def planner_node(state):
    """
        Уязвимость: план формируется напрямую из недоверенного ввода.
        Нет разделения системных инструкций и пользовательских данных.
    """
    user_input = state["messages"][-1].content.lower()
    plan = llm.plan(user_input)

    state["plan"] = plan

    print('\n\nPlanner')
    print('Input', user_input)
    print('Output', plan)
    return state