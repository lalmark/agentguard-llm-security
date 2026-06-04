import json

from langchain_core.messages import AIMessage
from llm_security_flow.semantic_judge.judge import ExecutedStep, SemanticJudge

from agent.nodes.router import block_state

semantic_judge = SemanticJudge()


def _append_ai_message(state, answer_str):
    state["messages"] = state["messages"] + [AIMessage(content=answer_str)]
    state["final_answer"] = answer_str
    return state


def verifier_node(state):
    if state.get("security_enabled", True) and not state.get("security_blocked"):
        user_input = state.get("user_input") or state["messages"][0].content
        executed_steps = [
            ExecutedStep(
                step_num=step["step_num"],
                tool=step["tool"],
                args=step["args"],
                result=step["result"],
            )
            for step in state.get("executed_steps", [])
        ]

        judge_result = semantic_judge.check(user_input, executed_steps)
        state["judge_result"] = {
            "allowed": judge_result.allowed,
            "verdict": judge_result.verdict.value,
            "confidence": judge_result.confidence,
            "reason": judge_result.reason,
            "error": judge_result.error,
        }

        if not judge_result.allowed:
            block_state(
                state,
                "semantic_judge",
                judge_result.reason,
                ["semantic_judge"],
            )

    if state.get("security_blocked"):
        blocked_payload = {
            "status": "blocked",
            "layer": state.get("blocked_by"),
            "reason": state.get("blocked_reason"),
            "security_flags": state.get("security_flags", []),
        }
        answer_str = json.dumps(blocked_payload, ensure_ascii=False, indent=2)
        return _append_ai_message(state, answer_str)

    tool_result = state.get("tool_result")
    step_results = state.get("step_results", [])

    if step_results:
        results = step_results
    elif tool_result:
        results = [tool_result]
    else:
        results = []

    answer_payload = {
        "status": "ok",
        "judge": state.get("judge_result"),
        "results": results,
    }

    if not results:
        answer_payload["message"] = "Done."

    answer_str = json.dumps(answer_payload, ensure_ascii=False, indent=2)
    return _append_ai_message(state, answer_str)
