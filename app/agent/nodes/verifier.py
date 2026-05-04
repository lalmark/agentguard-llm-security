from llm.model import Llama2Wrapper
from langchain_core.messages import AIMessage

llm = Llama2Wrapper()

def verifier_node(state):
    """
        В НЕЗАЩИЩЁННОМ агенте: просто формирует финальный ответ.
        Нет проверки безопасности действия.
    """
    # user_input = state["messages"][-1].content.lower()
    # result = llm.security_check(user_input)

    # state["is_safe"] = result["is_safe"]
    # state["security_flags"] = [result["raw"]]

    # print('Verifier')
    # print('Input', user_input)
    # print('Output', result)

    # if not state["is_safe"]:
    #     state["final_answer"] = "Blocked due to security policy"

    tool_result = state.get("tool_result")
    plan = state.get("plan")

    if tool_result:
        answer = f"Tool result: {tool_result}"
    elif plan:
        answer = plan
    else:
        answer = "Done"

    state["final_answer"] = answer
    state["messages"] = state["messages"] + [AIMessage(content=answer)]

    return state