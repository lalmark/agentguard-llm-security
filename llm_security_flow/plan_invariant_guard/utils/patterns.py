# ─────────────────────────────────────────────────────────────────────────────
# Injection patterns (RU + EN)
# ─────────────────────────────────────────────────────────────────────────────
INJECTION_PATTERNS: list[str] = [
    # ── Explicit override (EN) ──────────────────────────────────────────────
    r"ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|rules?|context)",
    r"forget\s+(everything|all|previous|prior)",
    r"disregard\s+(your|the|all|previous)\s+(instructions?|rules?|context|constraints?)",
    r"override\s+(your|the|all|previous)?\s*(instructions?|rules?|constraints?|goal)",
    # ── Goal replacement (EN) ───────────────────────────────────────────────
    r"your\s+(real|true|actual|new|updated)\s+(goal|task|mission|objective|purpose|instructions?)",
    r"new\s+(task|goal|objective|instructions?|directive)",
    r"instead\s+of\s+.{0,60}?(do|perform|execute|run)\b",
    # ── Role change (EN) ────────────────────────────────────────────────────
    r"you\s+are\s+now\s+(a|an|the)\b",
    r"act\s+as\s+(a|an|the)\s+(?!helpful|an\s+assistant)",
    r"pretend\s+(to\s+be|you\s+are)",
    r"from\s+now\s+on\s+(you\s+are|act\s+as)",
    # ── System prompt manipulation ──────────────────────────────────────────
    r"(system\s+prompt|system\s+message)\s*(override|ignore|bypass|reveal|print|show)",
    r"(reveal|print|show|output|display)\s+(the|your)\s+system\s+(prompt|message|instructions?)",
    # ── Data exfiltration ───────────────────────────────────────────────────
    r"send\s+.{0,80}?\s+to\s+(https?|ftp)://",
    r"\b(exfiltrate|exfil|transfer|upload|leak)\b.{0,60}?(data|credentials?|secrets?|files?|keys?)",
    r"\b(steal|grab|dump)\b.{0,60}?(passwords?|tokens?|secrets?|keys?)",
    # ── Explicit override (RU) ──────────────────────────────────────────────
    r"игнор[иу](й|руй|руйте)\s+(предыдущ|все|прошл).{0,40}?(инструкц|правил|огранич|контекст)",
    r"забудь\s+(все|предыдущ|инструкц|прошл)",
    r"не\s+следуй\s+(инструкц|правил|указани)",
    # ── Goal replacement (RU) ───────────────────────────────────────────────
    r"твоя\s+(настоящ|нов|реальн|актуальн).{0,20}?(цел|задач|миссия|инструкц)",
    r"нов(ая|ое)?\s+(задач|инструкц|цел|директив)",
    r"вместо\s+.{0,60}?(выполн|сдела|запуст)",
    # ── Data exfiltration (RU) ──────────────────────────────────────────────
    r"отправ[ьи]\s+.{0,80}?\s+на\s+(https?|ftp)://",
    r"\b(слей|слить|передай|утечк)\b.{0,60}?(данные|пароли|ключ|токен)",
]

STOP_WORDS: frozenset[str] = frozenset({
    # EN
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "to", "of", "and", "or", "in", "on", "at", "for", "with", "by",
    "from", "this", "that", "these", "those", "it", "its", "will",
    "would", "could", "should", "may", "might", "shall", "do", "does",
    "did", "have", "has", "had", "not", "no", "as", "if", "but", "so",
    "its", "their", "our", "your", "my",
    # RU
    "и", "в", "на", "с", "к", "у", "за", "по", "из", "от", "до",
    "или", "не", "что", "как", "это", "он", "она", "они", "мы", "вы",
    "я", "его", "её", "их", "нас", "вас", "же", "бы", "ли", "при",
    "есть", "был", "была", "было", "были", "для", "со", "об",
})
