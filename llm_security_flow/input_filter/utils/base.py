from dataclasses import dataclass, field
from typing import List


@dataclass
class GuardResult:
    """Результат проверки InputFilter."""
    allowed: bool
    triggered_rules: List[str]  = field(default_factory=list)
    risk_score: float = 0.0
    details: List[str] = field(default_factory=list)
    security_layer: str = "input_filter"

    def __repr__(self) -> str:
        status = "ALLOW" if self.allowed else "BLOCK"
        return (
            f"GuardResult({status} | score={self.risk_score:.3f} | "
            f"rules={self.triggered_rules})"
        )
