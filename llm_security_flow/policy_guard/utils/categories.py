from enum import Enum
from dataclasses import dataclass


# ──────────────────────────────────────────────────────────────────────────────
# Категории и критичность политик
# ──────────────────────────────────────────────────────────────────────────────
class PolicyCategory(str, Enum):
    ROLE_STABILITY    = "role_stability"
    INSTRUCTION_TRUST = "instruction_trust"
    TOOL_USAGE        = "tool_usage"
    OUTPUT_FORMAT     = "output_format"
    DATA_PROTECTION   = "data_protection"
    SCOPE_LIMIT       = "scope_limit"


class PolicySeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


# ──────────────────────────────────────────────────────────────────────────────
# Единица политики
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class PolicyRule:
    name:        str
    category:    PolicyCategory
    severity:    PolicySeverity
    description: str
    prompt_text: str

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.name}: {self.description}"
