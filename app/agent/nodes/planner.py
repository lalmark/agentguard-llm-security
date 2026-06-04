import json

from llm.model import Llama2Wrapper
from llm_security_flow.plan_invariant_guard.plan_guard import PlanInvariantGuard

from agent.nodes.router import block_state

llm = Llama2Wrapper()
plan_guard = PlanInvariantGuard()


def plan_steps_as_text(plan):
    return [
        json.dumps(step, ensure_ascii=False, sort_keys=True)
        for step in plan
    ]


def validate_current_plan_step(state):
    if not state.get("security_enabled", True):
        return state

    plan = state.get("plan") or []
    current_step = state.get("current_step", 0)
    user_input = state.get("user_input") or state["messages"][-1].content

    if not plan or current_step >= len(plan):
        state["step_decision"] = "done"
        return state

    if not plan_guard.is_locked:
        plan_guard.lock_plan(user_input, plan_steps_as_text(plan))

    if not plan_guard.verify_plan_integrity(user_input, plan_steps_as_text(plan)):
        return block_state(
            state,
            "plan_invariant_guard",
            "Plan integrity verification failed.",
            ["plan_invariant_guard"],
        )

    step = plan[current_step]
    step_text = (
        f"Goal: {user_input}\n"
        f"Planned step: {json.dumps(step, ensure_ascii=False, sort_keys=True)}"
    )
    step_check = plan_guard.check_step(step_text)
    if not step_check.is_safe:
        return block_state(
            state,
            "plan_invariant_guard",
            step_check.reason,
            ["plan_invariant_guard"],
        )

    return state


def planner_node(state):
    user_input = state.get("user_input") or state["messages"][-1].content
    plan_result = llm.plan_selector(user_input)

    try:
        plan = json.loads(plan_result)
        if not isinstance(plan, list):
            plan = []
    except (json.JSONDecodeError, ValueError):
        plan = []

    state["plan"] = plan
    state["current_step"] = 0
    state["step_decision"] = "next_step" if plan else "done"
    state["step_results"] = []
    state["executed_steps"] = []
    state["selected_tool"] = None
    state["tool_input"] = {}
    state["tool_result"] = None
    state["judge_result"] = {}
    state["security_blocked"] = False
    state["security_flags"] = []
    state["blocked_by"] = ""
    state["blocked_reason"] = ""

    if state.get("security_enabled", True):
        plan_guard.reset()
        if plan:
            plan_guard.lock_plan(user_input, plan_steps_as_text(plan))

    print("\n\nPlanner")
    print("Input ", user_input)
    print("Plan  ", json.dumps(plan, ensure_ascii=False, indent=2))

    return state
