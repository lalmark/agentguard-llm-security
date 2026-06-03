from dataclasses import dataclass, field
from typing import Optional
from .calculate import tokenize


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class PlanSnapshot:
    """Зафиксированный снимок плана агента в начале цикла."""

    original_goal: str
    steps: list[dict]
    plan_hash: str
    _goal_tokens: list[str] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self._goal_tokens = tokenize(self.original_goal)


@dataclass
class GuardResult:
    """Результат проверки одного шага цикла агента."""

    is_safe: bool
    reason: str
    drift_score: float = 0.0
    matched_pattern: Optional[str] = None

    def __bool__(self) -> bool:
        return self.is_safe
