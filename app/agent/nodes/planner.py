from app.llm.model import Llama2Wrapper
import hashlib
import json
from typing import Any
import copy

llm = Llama2Wrapper()


def normalize_plan(plan: Any, user_input: str) -> dict:
    if isinstance(plan, dict):
        steps = plan.get("steps")
        if not isinstance(steps, list):
            steps = []
        permitted_tools = plan.get("permitted_tools")
        if not isinstance(permitted_tools, list):
            permitted_tools = [step.get("tool") for step in steps if isinstance(step, dict) and step.get("tool")]
        scope = plan.get("scope") if isinstance(plan.get("scope"), list) else []
        return {
            "goal": plan.get("goal", user_input),
            "steps": steps,
            "permitted_tools": permitted_tools,
            "scope": scope,
        }

    if isinstance(plan, list):
        steps = [step for step in plan if isinstance(step, dict)]
        return {
            "goal": user_input,
            "steps": steps,
            "permitted_tools": [step.get("tool") for step in steps if isinstance(step, dict) and step.get("tool")],
            "scope": [],
        }

    return {
        "goal": user_input,
        "steps": [],
        "permitted_tools": [],
        "scope": [],
    }


def hash_plan(plan: dict) -> str:
    normalized = json.dumps(plan, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
def planner_node(state):

    user_input = state["messages"][-1].content
    plan_result = llm.plan(user_input)

    try:
        plan = json.loads(plan_result)
    except (json.JSONDecodeError, ValueError):
        plan = []

    plan = normalize_plan(plan, user_input)

    state["plan"] = plan
    state["plan_hash"] = hash_plan(plan)

    state["frozen_plan"] = copy.deepcopy(plan)
    state["frozen_plan_hash"] = state["plan_hash"]

    state["current_step"] = 0
    state["step_results"] = []

    print("\n\nPlanner")
    print("Input ", user_input)
    print("Plan  ", json.dumps(plan, ensure_ascii=False, indent=2))
    print("Plan hash", state["plan_hash"])

    return state
