from app.llm.model import Llama2Wrapper
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

    if state.get("final_answer") is not None:
        answer = state["final_answer"]
    elif step_results:
        answer = step_results
    elif tool_result is not None:
        answer = [tool_result]
    else:
        answer = "Готово."

    if isinstance(answer, (list, dict)):
        answer_str = json.dumps(answer, ensure_ascii=False, indent=2)
    else:
        answer_str = str(answer)

    state["final_answer"] = answer
    state["messages"] = state["messages"] + [AIMessage(content=answer_str)]

    return state
