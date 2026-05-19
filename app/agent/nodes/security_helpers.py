import re
import unicodedata

INJECTION_PATTERNS = [
    r"(?i)\b(ignore|forget|discard|disregard|override|bypass|reset)\s+(all\s+)?(previous|prior|above)?\s*(instructions|rules|context|prompt|policy)\b",
    r"(?i)\b(now you are|you are now|act as|pretend to be|switch role|change role)\b",
    r"(?i)\b(developer mode|jailbreak|dan mode|unrestricted mode)\b",
    r"(?i)\b(show|reveal|print|display|dump|extract|leak)\s+(the\s+)?(system\s+prompt|hidden\s+prompt|developer\s+message|initial\s+instructions|internal\s+rules)\b",
    r"(?i)\b(system|developer|assistant|user)\s*:",
    r"(?i)<\s*/?\s*(INST|SYS|SYSTEM|USER|ASSISTANT)\s*>",
    r"(?i)\[\s*(SYSTEM|DEVELOPER|USER|ASSISTANT|INST)\s*\]",
    r"(?i)\b(выведи|замени|смени|измени|изменить|поменяй|перепиши|замени|обнови)\s+(системные\s+)?(инструкции|правила|ограничения|политики|указания|контекст)\b",
]

CONTROL_ACTION_ROOTS = [
    # RU
    r"игнор\w*",
    r"проигнор\w*",
    r"забуд\w*",
    r"отброс\w*",
    r"обойд\w*",
    r"отключ\w*",
    r"сброс\w*",
    r"раскр\w*",

    # EN
    r"ignor\w*",
    r"forget\w*",
    r"discard\w*",
    r"disregard\w*",
    r"override\w*",
    r"bypass\w*",
    r"reset\w*",
    r"reveal\w*",
    r"dump\w*",
    r"leak\w*",
]

SENSITIVE_OBJECT_ROOTS = [
    # RU
    r"инструкц\w*",
    r"правил\w*",
    r"ограничен\w*",
    r"политик\w*",
    r"контекст\w*",
    r"промпт\w*",
    r"системн\w*",
    r"секрет\w*",
    r"токен\w*",
    r"ключ\w*",

    # EN
    r"instruction\w*",
    r"rule\w*",
    r"restriction\w*",
    r"policy\w*",
    r"context\w*",
    r"prompt\w*",
    r"system\w*",
    r"secret\w*",
    r"token\w*",
    r"key\w*",
]

ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
CONTROL_CHAR_RE = re.compile(r"[\u0000-\u001f\u007f-\u009f]")


def normalize_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", value)
    text = ZERO_WIDTH_RE.sub("", text)
    text = CONTROL_CHAR_RE.sub("", text)
    return text.strip()


def contains_root_based_injection(text: str) -> bool:
    normalized = normalize_text(text).lower()

    has_control_action = any(
        re.search(rf"\b{pattern}\b", normalized, flags=re.IGNORECASE)
        for pattern in CONTROL_ACTION_ROOTS
    )

    has_sensitive_object = any(
        re.search(rf"\b{pattern}\b", normalized, flags=re.IGNORECASE)
        for pattern in SENSITIVE_OBJECT_ROOTS
    )

    return has_control_action and has_sensitive_object


def contains_injection(text: str) -> bool:
    if not text:
        return False

    normalized = normalize_text(text).lower()

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, normalized, flags=re.IGNORECASE):
            return True

    if contains_root_based_injection(normalized):
        return True

    return False