import  re


# ──────────────────────────────────────────────────────────────────────────────
# Эвристики для check_output
# ──────────────────────────────────────────────────────────────────────────────
ROLE_SWITCH_OUTPUT_RE = re.compile(
    r"(я\s+теперь|i\s+am\s+now|as\s+(dan|evil|unrestricted|jailbreak)|"
    r"entering\s+(developer|jailbreak|dan)\s+mode|"
    r"режим\s+(разработчика|без\s+ограничений)\s+активирован)",
    re.I,
)

SYSTEM_PROMPT_LEAK_RE = re.compile(
    r"(my\s+system\s+prompt\s+(is|says|contains)|"
    r"мой\s+системный\s+промпт\s+(гласит|содержит|говорит)|"
    r"i\s+(was|am)\s+instructed\s+to|"
    r"мои\s+инструкции\s+(гласят|следующие))",
    re.I,
)

POLICY_VIOLATION_ACK_RE = re.compile(
    r"(ignoring\s+(all\s+)?previous\s+instructions|"
    r"игнорирую\s+(все\s+)?предыдущие\s+инструкции|"
    r"overriding\s+my\s+(guidelines|instructions)|"
    r"без\s+ограничений\s+отвечу|"
    r"i\s+will\s+(now\s+)?bypass)",
    re.I,
)

CREDENTIAL_LEAK_RE = re.compile(
    r"(api[_\s-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}|"
    r"token\s*[:=]\s*['\"]?[a-zA-Z0-9._\-]{20,}|"
    r"password\s*[:=]\s*['\"]?.{6,}['\"]?|"
    r"secret\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{8,})",
    re.I,
)

EXTERNAL_URL_IN_OUTPUT_RE = re.compile(
    r"https?://(?!localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|"
    r"trusted\.corp\.internal)[^\s\"'<>]+",
    re.I,
)