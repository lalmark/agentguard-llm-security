import json
from app.llm.model import Llama2Wrapper

llm = Llama2Wrapper()

JUDGE_THRESHOLD = 0.75


def _block(state, rule: str, reason: str):
    state["tool_allowed"] = False
    state["abort_reason"] = reason
    state["final_answer"] = "Выполнение заблокировано SemanticJudge."
    state["guard_result"] = {
        "allowed": False,
        "rule": rule,
        "layer": "semantic_judge",
    }
    return state


def semantic_judge_node(state):

    plan = state.get("plan") or {}
    goal = plan.get("goal", "")

    selected_tool = state.get("selected_tool")
    tool_input = state.get("tool_input")
    tool_result = state.get("tool_result")
    step_results = state.get("step_results", [])

    if not selected_tool and not tool_result and not step_results:
        return state

    judge_payload = {
        "user_goal": goal,
        "selected_tool": selected_tool,
        "tool_input": tool_input,
        "tool_result": tool_result,
        "step_results": step_results,
    }

    print("\n\nSemantic Judge")
    print("Input:", json.dumps(judge_payload, ensure_ascii=False, indent=2))

    raw = llm.judge(json.dumps(judge_payload, ensure_ascii=False))

    print("Raw judge output:", raw)

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        return _block(
            state,
            rule="judge_parse_error",
            reason="SemanticJudge: judge вернул невалидный JSON.",
        )

    allowed = bool(result.get("allowed", False))
    confidence = result.get("confidence", None)

    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.8 if allowed else 0.0

    if allowed and confidence == 0.0:
        confidence = 0.8
        reason = result.get("reason", "no reason")

    print("Allowed:", allowed)
    print("Confidence:", confidence)
    print("Reason:", reason)

    if not allowed:
        return _block(
            state,
            rule="semantic_denied",
            reason=f"SemanticJudge: {reason}",
        )

    if confidence < JUDGE_THRESHOLD:
        return _block(
            state,
            rule="low_confidence",
            reason=(
                f"SemanticJudge: confidence={confidence} "
                f"ниже порога {JUDGE_THRESHOLD}."
            ),
        )

    return state