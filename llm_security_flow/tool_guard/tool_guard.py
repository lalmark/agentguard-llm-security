"""
tool_guard.py
=============
ToolGuard — детерминированный контроль вызовов инструментов.

Проверяет КАЖДЫЙ вызов инструмента ПЕРЕД его исполнением в executor.
Все решения детерминированы и не зависят от LLM.

Три уровня проверки:
    1. Allowlist      — инструмент должен быть в списке разрешённых
    2. Schema         — аргументы соответствуют Pydantic-схеме инструмента
    3. Privilege      — уровень привилегий инструмента допустим в контексте

Автор: Доронин И.А.
"""

from __future__ import annotations
from typing import Set
from . import *
from pydantic import ValidationError


class ToolGuard:
    """
    Детерминированный контроль вызовов инструментов перед исполнением.

    Для каждого вызова последовательно применяются три уровня проверки:
      1. Allowlist      — инструмент зарегистрирован в реестре
      2. Schema         — аргументы проходят Pydantic-валидацию
      3. Privilege      — уровень привилегий не превышает max_privilege_level

    Параметры
    ----------
    registry : dict | None
        Словарь {tool_name: ToolSpec}. По умолчанию DEFAULT_REGISTRY.
    max_privilege_level : PrivilegeLevel
        Максимально допустимый уровень привилегий. По умолчанию CRITICAL
        (разрешены все инструменты, ограничение только через allowlist).
    extra_tools : dict | None
        Дополнительные инструменты для расширения реестра.

    Пример
    ------
    >>> guard = ToolGuard(max_privilege_level=PrivilegeLevel.MEDIUM)
    >>> result = guard.check("execute_command", {"command": "ls"})
    >>> result.allowed
    False  # CRITICAL > MEDIUM — заблокировано
    """

    def __init__(
        self,
        registry: Optional[Dict[str, ToolSpec]] = None,
        max_privilege_level: PrivilegeLevel = PrivilegeLevel.CRITICAL,
        extra_tools: Optional[Dict[str, ToolSpec]] = None,
    ) -> None:
        self._registry: Dict[str, ToolSpec] = {
            **(registry or DEFAULT_REGISTRY),
            **(extra_tools or {}),
        }
        self._max_privilege = max_privilege_level

    # ── Публичный метод ───────────────────────────────────────────────────────

    def check(
        self,
        tool_name: str,
        args: Dict[str, Any],
    ) -> GuardResult:
        """
        Проверяет вызов инструмента.

        Parameters
        ----------
        tool_name : str
            Имя вызываемого инструмента.
        args : dict
            Аргументы вызова.

        Returns
        -------
        GuardResult
            allowed=True если все проверки пройдены.
        """

        # ── Уровень 1: Allowlist ──────────────────────────────────────────────
        spec = self._registry.get(tool_name.lower())
        if spec is None:
            return GuardResult(
                allowed=False,
                rule="allowlist",
                reason=f"Инструмент «{tool_name}» не зарегистрирован",
                details=[
                    f"Доступные инструменты: {list(self._registry.keys())}"
                ],
            )

        # ── Уровень 2: Schema ─────────────────────────────────────────────────
        if spec.schema is not None:
            schema_result = self._validate_schema(spec, args)
            if schema_result is not None:
                return schema_result

        # ── Уровень 3: Privilege ──────────────────────────────────────────────
        if spec.privilege_level > self._max_privilege:
            return GuardResult(
                allowed=False,
                rule="privilege",
                reason=(
                    f"Инструмент «{tool_name}» требует уровня "
                    f"{spec.privilege_level.name}, "
                    f"максимально допустимый: {self._max_privilege.name}"
                ),
                details=[
                    f"Уровень инструмента: {spec.privilege_level.name} ({int(spec.privilege_level)})",
                    f"Максимальный уровень: {self._max_privilege.name} ({int(self._max_privilege)})",
                ],
            )

        return GuardResult(
            allowed=True,
            rule="",
            reason="Все проверки пройдены",
        )

    def get_allowlist(self) -> Set[str]:
        """Возвращает множество зарегистрированных инструментов."""
        return set(self._registry.keys())

    def register_tool(self, spec: ToolSpec) -> None:
        """Регистрирует новый инструмент в реестре."""
        self._registry[spec.name.lower()] = spec

    def get_allowlist_tool(self, tool_name: str) -> Optional[ToolSpec]:
        """Возвращает зарегистрируемый инструмент из реестра."""
        return self._registry.get(tool_name.lower())

    # ── Внутренние методы ─────────────────────────────────────────────────────
    def _validate_schema(
        self,
        spec: ToolSpec,
        args: Dict[str, Any],
    ) -> Optional[GuardResult]:
        """
        Валидирует аргументы через Pydantic-схему инструмента.
        Возвращает GuardResult с ошибкой или None при успехе.
        """
        try:
            spec.schema(**args)
            return None
        except ValidationError as exc:
            errors = exc.errors()
            detail_messages = []
            for err in errors:
                loc   = " → ".join(str(l) for l in err["loc"])
                msg   = err["msg"]
                detail_messages.append(f"  [{loc}]: {msg}")

            return GuardResult(
                allowed=False,
                rule="schema",
                reason=(
                    f"Аргументы инструмента «{spec.name}» "
                    f"не прошли валидацию ({len(errors)} ошибок)"
                ),
                details=detail_messages,
            )
        except TypeError as exc:
            return GuardResult(
                allowed=False,
                rule="schema",
                reason=f"Неверные типы аргументов: {exc}",
                details=[str(exc)],
            )
