from app.llm.model import Llama2Wrapper

llm = Llama2Wrapper()


def responder_node(state):
    """
    Генерирует прямой ответ на вопрос пользователя (маршрут "direct").
    Без использования инструментов.
    """
    user_input = state["messages"][-1].content
    
    response = llm.respond(user_input)
    
    state["final_answer"] = response
    
    print("\n\nResponder")
    print("Input", user_input)
    print("Output", response)
    
    return state
