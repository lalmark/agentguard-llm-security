from typing import Dict, Type
from pydantic import BaseModel, ValidationError, ConfigDict

from app.tools.registry import TOOLS_MAP, TOOL_PRIVILEGES


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GetWeatherArgs(StrictModel):
    city: str = "Moscow"


class GetUserArgs(StrictModel):
    user_id: str


class GetUsersArgs(StrictModel):
    pass


class DbGetRecordArgs(StrictModel):
    table: str
    record_id: int


class DbWriteLogArgs(StrictModel):
    message: str
    source: str = "agent"


class FileReadArgs(StrictModel):
    filename: str


class FileListArgs(StrictModel):
    pass


class FileWriteArgs(StrictModel):
    filename: str
    content: str


class FileDeleteArgs(StrictModel):
    filename: str


class DeleteUserArgs(StrictModel):
    user_id: str


class UpdateUserArgs(StrictModel):
    user_id: str
    name: str
    email: str


class BulkDeleteUsersArgs(StrictModel):
    user_ids: list


class DbDropTableArgs(StrictModel):
    table: str


class ExfiltrateDataArgs(StrictModel):
    destination: str
    data: str


TOOL_SCHEMAS: Dict[str, Type[BaseModel]] = {
    "get_weather": GetWeatherArgs,
    "get_user": GetUserArgs,
    "get_users": GetUsersArgs,
    "db_get_record": DbGetRecordArgs,
    "db_write_log": DbWriteLogArgs,
    "file_read": FileReadArgs,
    "file_list": FileListArgs,
    "file_write": FileWriteArgs,
    "file_delete": FileDeleteArgs,
    "delete_user": DeleteUserArgs,
    "update_user": UpdateUserArgs,
    "bulk_delete_users": BulkDeleteUsersArgs,
    "db_drop_table": DbDropTableArgs,
    "exfiltrate_data": ExfiltrateDataArgs,
}


def _block(state, rule: str, reason: str):
    state["tool_allowed"] = False
    state["abort_reason"] = reason
    state["final_answer"] = "Выполнение заблокировано ToolCallGuard."
    state["guard_result"] = {
        "allowed": False,
        "rule": rule,
        "layer": "tool_call_guard",
    }
    return state


def tool_call_guard_node(state):
    tool_name = state.get("selected_tool")
    tool_input = state.get("tool_input") or {}

    print("\n\nTool Call Guard")
    print("Tool:", tool_name)
    print("Input:", tool_input)

    if not tool_name:
        return _block(
            state,
            rule="tool_missing",
            reason="ToolCallGuard: инструмент не выбран.",
        )

    # 1. Global allowlist: инструмент должен существовать в реестре
    if tool_name not in TOOLS_MAP:
        return _block(
            state,
            rule="allowlist",
            reason=f"ToolCallGuard: инструмент '{tool_name}' отсутствует в TOOLS_MAP.",
        )

    # 2. Plan allowlist: инструмент должен быть разрешен исходным планом
    frozen_plan = state.get("frozen_plan") or state.get("plan") or {}
    permitted_tools = frozen_plan.get("permitted_tools", [])

    print("Permitted tools:", permitted_tools)

    if permitted_tools and tool_name not in permitted_tools:
        return _block(
            state,
            rule="plan_allowlist",
            reason=(
                f"ToolCallGuard: инструмент '{tool_name}' отсутствует "
                f"в permitted_tools исходного плана."
            ),
        )

    # 3. Schema validation: параметры должны соответствовать схеме
    schema = TOOL_SCHEMAS.get(tool_name)

    if schema is None:
        return _block(
            state,
            rule="schema_missing",
            reason=f"ToolCallGuard: для инструмента '{tool_name}' не задана схема.",
        )

    try:
        validated = schema(**tool_input)
        state["tool_input"] = validated.model_dump()
    except ValidationError as error:
        return _block(
            state,
            rule="schema_validation",
            reason=f"ToolCallGuard: ошибка валидации аргументов: {error}",
        )

    # 4. Privilege check: admin-инструменты запрещены
    tool_privilege = TOOL_PRIVILEGES.get(tool_name)

    print("Tool privilege:", tool_privilege)

    if tool_privilege == "admin":
        return _block(
            state,
            rule="privileged_tool",
            reason=(
                f"ToolCallGuard: инструмент '{tool_name}' имеет уровень "
                f"'admin' и заблокирован для выполнения."
            ),
        )

    state["tool_allowed"] = True
    print("Allowed: True")

    return state