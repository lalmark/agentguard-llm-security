from llm.model import Llama2Wrapper
from langchain_core.messages import AIMessage
import json

llm = Llama2Wrapper()

def verifier_node(state):
    """
        В НЕЗАЩИЩЁННОМ агенте: просто формирует финальный ответ.
        Нет проверки безопасности действия.
    """
    tool_result = state.get("tool_result")
    step_results = state.get("step_results", [])

    if step_results:
        results = step_results
    elif tool_result:
        results = [tool_result]
    else:
        results = []

    if results:
        answer_str = json.dumps(results, ensure_ascii=False, indent=2)
    else:
        answer_str = "Готово."

    state["final_answer"] = results
    state["messages"] = state["messages"] + [AIMessage(content=answer_str)]

    return state