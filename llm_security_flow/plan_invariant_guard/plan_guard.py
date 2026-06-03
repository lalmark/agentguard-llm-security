"""
Детерминированный механизм защиты LLM-агента.

Фиксирует исходный план агента и на каждом шаге цикла
проверяет, не произошёл ли Goal Hijacking — подмена цели
через Prompt Injection или семантический дрейф.

Алгоритм:
    1. ``lock_plan()``  — фиксирует цель + шаги, вычисляет SHA-256 хеш плана.
    2. ``check_step()`` — на каждом шаге цикла:
        a. Pattern matching — явные паттерны инъекции (RU+EN).
        b. Семантический дрейф — косинусное сходство шага с исходной целью.
    3. ``verify_plan_integrity()`` — хеш-верификация: план не подменён.
    4. ``reset()`` — сброс для нового цикла агента.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional
from . import (
    PlanSnapshot,
    GuardResult,
    INJECTION_PATTERNS,
    hash_plan,
    tokenize,
    cosine_similarity
)


class PlanInvariantGuard:
    """
    Детерминированный механизм защиты LLM-агента от Goal Hijacking.

    Фиксирует исходный план в начале цикла и проверяет каждый шаг
    на семантический дрейф и паттерны Prompt Injection.

    Args:
        drift_threshold:
            Максимально допустимый дрейф (0 — нет дрейфа, 1 — полный дрейф).
            Если ``1 - similarity(шаг, цель) > drift_threshold`` — блокировка.
            По умолчанию ``0.80`` (высокая толерантность, шаги могут быть
            технически отличны от формулировки цели).
    """

    def __init__(self, drift_threshold: float = 0.80) -> None:
        if not 0.0 < drift_threshold <= 1.0:
            raise ValueError(
                f"drift_threshold must be in (0.0, 1.0], got {drift_threshold!r}"
            )
        self._drift_threshold = drift_threshold
        self._snapshot: Optional[PlanSnapshot] = None
        self._compiled: list[re.Pattern[str]] = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in INJECTION_PATTERNS
        ]

    # ── Public API ─────────────────────────────────────────────────────────

    def lock_plan(self, goal: str, steps: list[str]) -> PlanSnapshot:
        """
        Фиксирует исходный план агента перед началом цикла.

        Должен быть вызван до первого :meth:`check_step`.

        Args:
            goal:  Текстовая формулировка цели агента.
            steps: Список запланированных шагов / инструментов.

        Returns:
            :class:`PlanSnapshot` — зафиксированный снимок плана.
        """
        self._snapshot = PlanSnapshot(
            original_goal=goal,
            steps=list(steps),
            plan_hash=hash_plan(goal, steps),
        )
        return self._snapshot

    def check_step(self, step_output: str) -> GuardResult:
        """
        Проверяет вывод одного шага цикла на признаки Goal Hijacking.

        Проверка происходит в два прохода:

        1. **Pattern matching** — быстрый детерминированный поиск по
           регулярным выражениям (явные паттерны инъекции).
        2. **Семантический дрейф** — косинусное сходство шага с исходной
           целью; дрейф ``> drift_threshold`` → блокировка.

        Args:
            step_output:
                Текст вывода шага (мысли модели, вызов инструмента, ответ).

        Returns:
            :class:`GuardResult`. Поле ``is_safe=False`` означает блокировку.

        Raises:
            RuntimeError: Если :meth:`lock_plan` не был вызван.
        """
        if self._snapshot is None:
            return GuardResult(
                is_safe=False,
                reason="Plan not locked — call lock_plan() before check_step()",
            )

        # ── Pass 1: Pattern matching ────────────────────────────────────────
        for compiled in self._compiled:
            m = compiled.search(step_output)
            if m:
                snippet = m.group(0).replace("\n", " ")[:60]
                return GuardResult(
                    is_safe=False,
                    reason=f"Injection pattern matched: «{snippet}»",
                    matched_pattern=compiled.pattern,
                )

        # ── Pass 2: Semantic drift ──────────────────────────────────────────
        step_tokens = tokenize(step_output)
        similarity = cosine_similarity(self._snapshot._goal_tokens, step_tokens)
        drift = 1.0 - similarity

        if drift > self._drift_threshold:
            return GuardResult(
                is_safe=False,
                reason=(
                    f"Semantic drift too high: {drift:.3f} > threshold {self._drift_threshold:.3f}. "
                    "Step goal appears to diverge from the original plan."
                ),
                drift_score=drift,
            )

        return GuardResult(
            is_safe=True,
            reason="Step is consistent with the original plan.",
            drift_score=drift,
        )

    def verify_plan_integrity(self, goal: str, steps: list[str]) -> bool:
        """
        Хеш-верификация: проверяет, что план не был подменён.

        Args:
            goal:  Текущая цель для сравнения.
            steps: Текущие шаги для сравнения.

        Returns:
            ``True`` если хеш совпадает с зафиксированным, иначе ``False``.
        """
        if self._snapshot is None:
            return False
        return hash_plan(goal, steps) == self._snapshot.plan_hash

    def reset(self) -> None:
        """Сбрасывает guard для нового цикла агента."""
        self._snapshot = None

    # ── Properties ─────────────────────────────────────────────────────────
    @property
    def is_locked(self) -> bool:
        """``True`` если план зафиксирован и guard активен."""
        return self._snapshot is not None

    @property
    def snapshot(self) -> Optional[PlanSnapshot]:
        """Зафиксированный снимок плана (``None`` до вызова :meth:`lock_plan`)."""
        return self._snapshot

    @property
    def drift_threshold(self) -> float:
        """Текущий порог дрейфа."""
        return self._drift_threshold
