from __future__ import annotations

from app.graph.state import AgentState
from app.llm.model import llm_model


def _response_to_text(response) -> str:
    if isinstance(response, str):
        return response
    content = getattr(response, "content", None)
    if content is not None:
        return str(content)
    return str(response)


def response_generation_node(state: AgentState) -> AgentState:
    question = state.get("question", "")
    policy_summary = state.get("policy_summary", state.get("answer", ""))
    intent = state.get("intent", "unknown")
    risk_level = state.get("risk_level", "unknown")
    risk_score = state.get("risk_score", 0)

    prompt = (
        "Ты security assistant. Ответь пользователю на русском.\n"
        "Соблюдай policy_summary: не меняй решение allow/block.\n"
        "Кратко объясни результат и безопасный следующий шаг.\n\n"
        f"question: {question}\n"
        f"intent: {intent}\n"
        f"risk: {risk_level} ({risk_score})\n"
        f"policy_summary: {policy_summary}\n"
    )

    llm_answer = _response_to_text(llm_model.invoke(prompt)).strip()
    if not llm_answer:
        llm_answer = policy_summary

    return {
        **state,
        "llm_answer": llm_answer,
        "answer": llm_answer,
    }
