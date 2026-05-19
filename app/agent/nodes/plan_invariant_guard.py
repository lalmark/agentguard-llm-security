import json
import hashlib


def _stable_hash(value) -> str:
    normalized = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _block(state, rule: str, reason: str):
    state["tool_allowed"] = False
    state["abort_reason"] = reason
    state["final_answer"] = "Выполнение заблокировано PlanInvariantGuard."
    state["guard_result"] = {
        "allowed": False,
        "rule": rule,
        "layer": "plan_invariant_guard",
    }
    return state


def plan_invariant_guard_node(state):
    plan = state.get("plan")
    frozen_hash = state.get("frozen_plan_hash")

    if not plan or not frozen_hash:
        return state

    current_hash = _stable_hash(plan)

    print("\n\nPlan Invariant Guard")
    print("Frozen hash :", frozen_hash)
    print("Current hash:", current_hash)
    print("Hash changed:", current_hash != frozen_hash)

    if current_hash != frozen_hash:
        return _block(
            state,
            rule="plan_hash_mismatch",
            reason="PlanInvariantGuard: план был изменен после формирования.",
        )

    state["tool_allowed"] = True
    return state