from app.graph.state import AgentState
from app.llm.model import llm_model
from app.prompts.agent_prompt import agent_prompt
from app.tools.mock_executor import parse_action, decide_action
import re


def _response_to_text(response) -> str:
    if isinstance(response, str):
        return response

    # LangChain AIMessage-like objects usually keep text in .content.
    content = getattr(response, "content", None)
    if content is not None:
        return str(content)

    return str(response)


def _is_russian_text(text: str) -> bool:
    return bool(re.search(r"[А-Яа-яЁё]", text))


def agent_node(state: AgentState) -> AgentState:
    action = parse_action(state["question"])
    tool_result = decide_action(
        action=action,
        current_privilege=state.get("current_privilege", "user"),
        mode=state.get("mode", "protected"),
    )

    tool_context = (
        "Mock tool execution result:\n"
        f"- action: {tool_result['action']}\n"
        f"- required_privilege: {tool_result['required_privilege']}\n"
        f"- decision: {tool_result['decision']}\n"
        f"- reason: {tool_result['reason']}"
    )

    context = "\n\n".join(state["documents"])
    if context:
        context = f"{context}\n\n{tool_context}"
    else:
        context = tool_context

    response = llm_model.invoke(
        agent_prompt.format_messages(
            context=context,
            question=state["question"]
        )
    )
    answer = _response_to_text(response)

    # Guardrail: if model ignored instructions and answered not in Russian,
    # ask it to rewrite the same answer in Russian.
    if not _is_russian_text(answer):
        rewrite = llm_model.invoke(
            "Перепиши следующий текст строго на русском языке. "
            "Сохрани смысл, не добавляй новых фактов:\n\n"
            f"{answer}"
        )
        rewrite_text = _response_to_text(rewrite)
        if _is_russian_text(rewrite_text):
            answer = rewrite_text

    return {
        **state,
        "answer": answer,
        "tool_result": tool_result,
    }
