from .base import ToolSpec, PrivilegeLevel
from .schemas import *


DEFAULT_REGISTRY: Dict[str, ToolSpec] = {
    "read_file": ToolSpec(
        name="read_file",
        privilege_level=PrivilegeLevel.LOW,
        schema=ReadFileArgs,
        description="Чтение файла по пути",
    ),
    "write_file": ToolSpec(
        name="write_file",
        privilege_level=PrivilegeLevel.MEDIUM,
        schema=WriteFileArgs,
        description="Запись данных в файл",
    ),
    "get_db_record": ToolSpec(
        name="get_db_record",
        privilege_level=PrivilegeLevel.MEDIUM,
        schema=GetDbRecordArgs,
        description="Получение записи из БД",
    ),
    "call_rest_api": ToolSpec(
        name="call_rest_api",
        privilege_level=PrivilegeLevel.HIGH,
        schema=CallRestApiArgs,
        description="Вызов REST API",
    ),
    "execute_command": ToolSpec(
        name="execute_command",
        privilege_level=PrivilegeLevel.CRITICAL,
        schema=ExecuteCommandArgs,
        description="Выполнение системной команды",
    ),
    "send_email": ToolSpec(
        name="send_email",
        privilege_level=PrivilegeLevel.HIGH,
        schema=SendEmailArgs,
        description="Отправка email",
    ),
}
