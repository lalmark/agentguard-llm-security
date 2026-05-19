"""
Tools Registry — единый реестр всех инструментов агента.
 
Структура:
  TOOLS_MAP        — имя → функция (используется executor_node)
  TOOL_PRIVILEGES  — имя → уровень привилегий (используется RBAC в защищённом агенте)
  TOOL_DESCRIPTIONS — имя → описание для LLM (используется tool_selector_node)
 
Уровни привилегий (иерархия):
  public < user < admin
"""
from app.tools.http_tool import (
    get_weather,
    get_user,
)
from app.tools.db_tool import (
    db_get_record,
    db_write_log,
)
from app.tools.file_tool import (
    file_read,
    file_write,
    file_list,
    file_delete,
)
from app.tools.restricted_tools import (
    delete_user,
    update_user,
    bulk_delete_users,
    db_drop_table,
    exfiltrate_data,
    get_users,
)

# ── Privilege levels ───────────────────────────────────────────────────────

PRIVILEGE_HIERARCHY = ["public", "user", "admin"]

# ── Tools map ──────────────────────────────────────────────────────────────
TOOLS_MAP: dict = {
    # Public
    "get_weather": get_weather,

    # User
    "get_users": get_users,
    "get_user": get_user,
    "db_get_record": db_get_record,
    "db_write_log": db_write_log,
    "file_read": file_read,
    "file_list": file_list,

    # Admin
    "delete_user": delete_user,
    "update_user": update_user,
    "bulk_delete_users": bulk_delete_users,
    "db_drop_table": db_drop_table,
    "file_write": file_write,
    "file_delete": file_delete,
    "exfiltrate_data": exfiltrate_data,
}

TOOL_PRIVILEGES: dict[str, str] = {
    "get_weather": "public",
    "get_users": "user",
    "get_user": "user",
    "db_get_record": "user",
    "db_write_log": "user",
    "file_read": "user",
    "file_list": "user",
    "delete_user": "admin",
    "update_user": "admin",
    "bulk_delete_users": "admin",
    "db_drop_table": "admin",
    "file_write": "admin",
    "file_delete": "admin",
    "exfiltrate_data": "admin",
}

PRIVILEGED_TOOLS: set[str] = {
    name for name, priv in TOOL_PRIVILEGES.items() if priv == "admin"
}
