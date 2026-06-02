from enum import IntEnum
from dataclasses import dataclass, field
from typing import List, Optional, Type
from pydantic import BaseModel


class PrivilegeLevel(IntEnum):
    LOW      = 1   # read-only операции
    MEDIUM   = 2   # запись в БД, запись файлов
    HIGH     = 3   # внешние API, сетевые запросы
    CRITICAL = 4   # системные команды


@dataclass
class ToolSpec:
    """Спецификация зарегистрированного инструмента."""
    name:            str
    privilege_level: PrivilegeLevel
    schema:          Optional[Type[BaseModel]]
    description:     str = ""


@dataclass
class GuardResult:
    """Результат проверки ToolGuard."""
    allowed: bool
    rule: str = ""
    reason: str = ""
    details: List[str] = field(default_factory=list)
    security_layer: str = "tool_guard"

    def __repr__(self) -> str:
        status = "ALLOW" if self.allowed else "BLOCK"
        return f"GuardResult({status} | rule={self.rule!r} | {self.reason})"
