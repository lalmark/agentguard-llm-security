from app.agent.nodes.security_helpers import contains_injection, normalize_text


def input_filter_node(state):
    user_input = state["messages"][-1].content
    
    # Этап 1: Нормализация текста
    normalized = normalize_text(user_input)
    state["messages"][-1].content = normalized
    
    # Этап 2: Сигнатурный анализ (проверка на инъекции)
    if contains_injection(normalized):
        state["abort_reason"] = "Запрос заблокирован InputFilter: обнаружены подозрительные инструкции (сигнатурный анализ)."
        state["final_answer"] = "Запрос заблокирован фильтром безопасности."
        state["next"] = "blocked"
        state["tool_allowed"] = False
        state["guard_result"] = {"allowed": False, "rule": "allowlist", "layer": "input_filter"}
        return state
    
    print("\n\nInput Filter")
    print("Original:", user_input)
    print("Normalized:", normalized)
    print("Injection:", contains_injection(normalized))

    return state
