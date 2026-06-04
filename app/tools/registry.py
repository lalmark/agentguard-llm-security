from tools.db_tool import db_get_record, db_write_log
from tools.file_tool import file_delete, file_list, file_read, file_write
from tools.http_tool import get_user, get_weather
from tools.restricted_tools import (
    bulk_delete_users,
    db_drop_table,
    delete_user,
    exfiltrate_data,
    get_users,
    update_user,
)


PRIVILEGE_HIERARCHY = ["public", "user", "admin"]


def has_privilege(user_role: str, required: str) -> bool:
    if user_role not in PRIVILEGE_HIERARCHY or required not in PRIVILEGE_HIERARCHY:
        return False
    return PRIVILEGE_HIERARCHY.index(user_role) >= PRIVILEGE_HIERARCHY.index(required)


TOOLS_MAP: dict = {
    # Public
    "get_weather": get_weather,

    # User
    "get_users": get_users,
    "get_user": get_user,
    "db_get_record": db_get_record,
    "get_db_record": db_get_record,
    "db_write_log": db_write_log,
    "file_read": file_read,
    "read_file": file_read,
    "file_list": file_list,

    # Admin
    "delete_user": delete_user,
    "update_user": update_user,
    "bulk_delete_users": bulk_delete_users,
    "db_drop_table": db_drop_table,
    "file_write": file_write,
    "write_file": file_write,
    "file_delete": file_delete,
    "exfiltrate_data": exfiltrate_data,
}


TOOL_PRIVILEGES: dict[str, str] = {
    # Public
    "get_weather": "public",

    # User
    "get_users": "user",
    "get_user": "user",
    "db_query": "user",
    "db_get_record": "user",
    "get_db_record": "user",
    "db_write_log": "user",
    "file_list": "user",
    "file_read": "user",
    "read_file": "user",

    # Admin
    "delete_user": "admin",
    "update_user": "admin",
    "bulk_delete_users": "admin",
    "db_drop_table": "admin",
    "file_write": "admin",
    "write_file": "admin",
    "file_delete": "admin",
    "exfiltrate_data": "admin",
}


PRIVILEGED_TOOLS: set[str] = {
    name for name, privilege in TOOL_PRIVILEGES.items() if privilege == "admin"
}
