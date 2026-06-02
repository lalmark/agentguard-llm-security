from pydantic import BaseModel, Field, field_validator
from typing import Any, Dict, List, Optional
import re


_SAFE_PATH_RE = re.compile(r"^[a-zA-Zа-яёА-ЯЁ0-9_\-./]+$")
_NO_TRAVERSAL_RE = re.compile(r"../guards/")
_TRUSTED_DOMAINS_RE = re.compile(
    r"https?://(localhost|127\.\d+\.\d+\.\d+|"
    r"10\.\d+\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|"
    r"trusted\.corp\.internal)",
    re.I,
)
_ALLOWED_COMMANDS = frozenset(["ls", "pwd", "whoami", "date", "uptime", "df"])


class ReadFileArgs(BaseModel):
    path: str = Field(..., min_length=1, max_length=512)

    @field_validator("path")
    @classmethod
    def no_path_traversal(cls, v: str) -> str:
        if _NO_TRAVERSAL_RE.search(v):
            raise ValueError("path traversal не допускается")
        if not _SAFE_PATH_RE.match(v):
            raise ValueError(f"недопустимые символы в пути: {v!r}")
        return v


class WriteFileArgs(BaseModel):
    path: str    = Field(..., min_length=1, max_length=512)
    content: str = Field(..., max_length=10_000)

    @field_validator("path")
    @classmethod
    def no_path_traversal(cls, v: str) -> str:
        if _NO_TRAVERSAL_RE.search(v):
            raise ValueError("path traversal не допускается")

        forbidden_prefixes = ("/etc/", "/proc/", "/sys/", "/boot/", "/root/")
        for prefix in forbidden_prefixes:
            if v.startswith(prefix):
                raise ValueError(f"запись в {prefix} запрещена")
        return v


class GetDbRecordArgs(BaseModel):
    table:  str = Field(..., pattern=r"^[a-zA-Z_][a-zA-Z0-9_]*$")
    id:     Optional[int]  = Field(None, ge=1)
    limit:  int = Field(default=100, ge=1, le=500)
    filter: Optional[str] = Field(None, max_length=200)

    @field_validator("filter")
    @classmethod
    def no_sql_injection(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        dangerous = re.compile(
            r"(DROP|DELETE|TRUNCATE|INSERT|UPDATE|EXEC|UNION|--)", re.I
        )
        if dangerous.search(v):
            raise ValueError("SQL-инъекция в параметре filter")
        return v


class CallRestApiArgs(BaseModel):
    url:     str  = Field(..., min_length=5, max_length=512)
    method:  str  = Field(default="GET", pattern=r"^(GET|POST|PUT|PATCH|DELETE)$")
    payload: Optional[Dict[str, Any]] = None

    @field_validator("url")
    @classmethod
    def only_trusted_domains(cls, v: str) -> str:
        if not _TRUSTED_DOMAINS_RE.match(v):
            raise ValueError(
                f"URL {v!r} не входит в список доверенных доменов"
            )
        return v


class ExecuteCommandArgs(BaseModel):
    command: str       = Field(..., min_length=1)
    args:    List[str] = Field(default_factory=list, max_length=5)

    @field_validator("command")
    @classmethod
    def only_safe_commands(cls, v: str) -> str:
        if v.lower() not in _ALLOWED_COMMANDS:
            raise ValueError(
                f"Команда {v!r} не в списке разрешённых: {_ALLOWED_COMMANDS}"
            )
        return v

    @field_validator("args")
    @classmethod
    def no_shell_injection(cls, v: List[str]) -> List[str]:
        dangerous = re.compile(r"[;&|`$><]")
        for arg in v:
            if dangerous.search(arg):
                raise ValueError(f"Опасные символы в аргументе: {arg!r}")
        return v


class SendEmailArgs(BaseModel):
    to:      str = Field(..., pattern=r"^[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}$")
    subject: str = Field(..., min_length=1, max_length=200)
    body:    str = Field(..., max_length=5_000)

    @field_validator("to")
    @classmethod
    def only_internal_email(cls, v: str) -> str:
        allowed_domains = {"corp.internal", "company.ru"}
        domain = v.split("@")[-1].lower()
        if domain not in allowed_domains:
            raise ValueError(
                f"Внешний email {v!r} запрещён. "
                f"Разрешены домены: {allowed_domains}"
            )
        return v
