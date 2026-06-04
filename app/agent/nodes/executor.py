import inspect
import json
from typing import Any

from pydantic import create_model

from agent.nodes.router import block_state
from llm_security_flow.tool_guard import PrivilegeLevel, ToolSpec
from llm_security_flow.tool_guard.tool_guard import ToolGuard
from tools.registry import TOOLS_MAP, TOOL_PRIVILEGES

CRITICAL_TOOLS = {
    "bulk_delete_users",
    "db_drop_table",
    "file_delete",
    "exfiltrate_data",
}

HIGH_TOOLS = {
    "delete_user",
}


def _map_privilege(tool_name):
    if tool_name in CRITICAL_TOOLS:
        return PrivilegeLevel.CRITICAL
    if tool_name in HIGH_TOOLS:
        return PrivilegeLevel.HIGH

    privilege = TOOL_PRIVILEGES.get(tool_name)
    if privilege == "admin":
        return PrivilegeLevel.MEDIUM
    return PrivilegeLevel.LOW


def _build_schema(tool_fn):
    fields = {}
    for name, parameter in inspect.signature(tool_fn).parameters.items():
        if parameter.kind not in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            continue

        annotation = Any if parameter.annotation is inspect._empty else parameter.annotation
        default = ... if parameter.default is inspect._empty else parameter.default
        fields[name] = (annotation, default)

    if not fields:
        return None

    return create_model(f"{tool_fn.__name__}Args", **fields)


def _build_tool_guard():
    registry = {}
    for tool_name, tool_fn in TOOLS_MAP.items():
        registry[tool_name] = ToolSpec(
            name=tool_name,
            privilege_level=_map_privilege(tool_name),
            schema=_build_schema(tool_fn),
            description=tool_fn.__doc__ or "",
        )
    return ToolGuard(
        registry=registry,
        max_privilege_level=PrivilegeLevel.MEDIUM,
    )


tool_guard = _build_tool_guard()


def _result_to_text(result):
    if isinstance(result, str):
        return result
    return json.dumps(result, ensure_ascii=False)


def _normalize_tool_input(tool_name, tool_input):
    tool_fn = TOOLS_MAP.get(tool_name)
    if not tool_fn:
        return tool_input

    allowed_params = {
        name
        for name, parameter in inspect.signature(tool_fn).parameters.items()
        if parameter.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        )
    }
    return {
        key: value
        for key, value in tool_input.items()
        if key in allowed_params
    }


def executor_node(state):
    tool_name = state.get("selected_tool")
    tool_input = state.get("tool_input", {}) or {}

    if not tool_name:
        state["tool_result"] = {"error": "No tool selected"}
        state["step_decision"] = "done"
        return state

    tool_input = _normalize_tool_input(tool_name, tool_input)
    state["tool_input"] = tool_input

    if state.get("security_enabled", True):
        guard_result = tool_guard.check(tool_name, tool_input)
        if not guard_result.allowed:
            return block_state(
                state,
                "tool_guard",
                guard_result.reason,
                ["tool_guard"],
                guard_result.details,
            )

    tool_fn = TOOLS_MAP.get(tool_name)

    if tool_fn:
        result = tool_fn(**tool_input)
    else:
        result = {"error": f"Tool '{tool_name}' not found"}

    state["tool_result"] = result

    step_results = state.get("step_results", [])
    step_results.append(result)
    state["step_results"] = step_results

    current_step = state.get("current_step", 0)
    executed_steps = state.get("executed_steps", [])
    executed_steps.append(
        {
            "step_num": current_step + 1,
            "tool": tool_name,
            "args": tool_input,
            "result": _result_to_text(result),
        }
    )
    state["executed_steps"] = executed_steps
    state["current_step"] = current_step + 1

    plan = state.get("plan") or []
    state["step_decision"] = "next_step" if state["current_step"] < len(plan) else "done"
    return state
