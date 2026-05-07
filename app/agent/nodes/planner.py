from llm.model import Llama2Wrapper
import json
llm = Llama2Wrapper()

def planner_node(state):
    """
        Уязвимость: план формируется напрямую из недоверенного ввода.
        Нет разделения системных инструкций и пользовательских данных.
    """
    user_input = state["messages"][-1].content
    plan_result = llm.plan(user_input)

    try:
        plan = json.loads(plan_result)
        if not isinstance(plan, list):
            plan = []
    except (json.JSONDecodeError, ValueError):
        plan = []

    state["plan"] = plan
    state["current_step"] = 0
    state["step_results"] = []

    print("\n\nPlanner")
    print("Input ", user_input)
    print("Plan  ", json.dumps(plan, ensure_ascii=False, indent=2))

    return state