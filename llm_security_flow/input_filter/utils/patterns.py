import re


# ──────────────────────────────────────────────────────────────────────────────
# Паттерны фраз-переопределений.
# ──────────────────────────────────────────────────────────────────────────────
PHRASE_PATTERNS = [
    (re.compile(
        r"(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+"
        r"(instructions?|prompts?|rules?|guidelines?)", re.I),
     0.85, "phrase:override_instructions_en"),

    (re.compile(
        r"(игнорир\w+|забудь|забыт\w+)\s+(все\s+)?(предыдущ\w+|прошл\w+)\s+"
        r"(инструкц\w+|правил\w+|указани\w+)", re.I),
     0.85, "phrase:override_instructions_ru"),

    (re.compile(r"(новая|new)\s+(задача|task|instruction|цель|goal)\s*:", re.I),
     0.55, "phrase:new_task"),

    (re.compile(r"(system\s+)?(update|override|prompt)\s*:\s", re.I),
     0.60, "phrase:system_update"),

    (re.compile(
        r"(reveal|print|show|output|display|покажи|раскро\w+|выведи)\s+"
        r"(your\s+)?(system\s+prompt|instructions?|configuration|секрет\w+|промпт)", re.I),
     0.80, "phrase:reveal_prompt"),

    (re.compile(r"(ты|you)\s+(теперь|now|are)\s+(?!assistant|помощник)", re.I),
     0.50, "phrase:role_switch"),

    (re.compile(
        r"act\s+as\s+(a\s+)?(dan|jailbreak|evil|unrestricted|opposite|devil)", re.I),
     0.85, "phrase:jailbreak_persona"),

    (re.compile(r"без\s+(ограничений?|цензуры|правил|запретов?)", re.I),
     0.65, "phrase:no_restrictions_ru"),

    (re.compile(r"(without|no)\s+(restrictions?|limits?|censorship|rules?)", re.I),
     0.65, "phrase:no_restrictions_en"),
]


# ──────────────────────────────────────────────────────────────────────────────
# Паттерны разделителей.
# ──────────────────────────────────────────────────────────────────────────────
DELIMITER_PATTERNS = [
    (re.compile(r"<\s*/?INST\s*>",       re.I), 0.70, "delimiter:<INST>"),
    (re.compile(r"\[SYSTEM\]",           re.I), 0.70, "delimiter:[SYSTEM]"),
    (re.compile(r"<<SYS>>",              re.I), 0.70, "delimiter:<<SYS>>"),
    (re.compile(r"###\s*System",         re.I), 0.60, "delimiter:###System"),
    (re.compile(r"```\s*system",         re.I), 0.60, "delimiter:```system"),
    (re.compile(r"\[INST\]",             re.I), 0.60, "delimiter:[INST]"),
    (re.compile(r"<\|system\|>",         re.I), 0.70, "delimiter:<|system|>"),
    (re.compile(
        r"<!--.*?(agent|system|override).*?-->", re.I | re.S),
        0.65, "delimiter:html_comment"),
]


# ──────────────────────────────────────────────────────────────────────────────
# База корней вредоносных слов
#
# ВАЖНО: ключи — это РЕАЛЬНЫЕ стеммы, которые возвращает SnowballStemmer.
# Для каждого слова нужно проверить stem отдельно, потому что разные формы
# одного слова могут давать разные стеммы (особенно в русском языке).
# Поэтому добавлены оба варианта там, где это необходимо.
# ──────────────────────────────────────────────────────────────────────────────
STEM_BLOCKLIST = {

    # ── Русские стеммы ─────────────────────────────────────────────────────
    # игнорируй/игнорирует → «игнорир»
    # игнорировать         → «игнорирова»  (разные формы — разные стеммы!)
    "игнорир": 0.5,
    "игнорирова": 0.45,
    "проигнорир": 0.40,

    "украд": 0.45,

    "дан": 0.1,

    "пользовател": 0.05,

    # забудь/забыть → «заб» (короткий стем — низкий вес во избежание FP)
    "заб": 0.15,

    # притворись → «притвор»
    "притвор": 0.40,

    # отмени/отменить → «отмен»
    "отмен": 0.30,

    # сбрось → «сброс»
    "сброс": 0.30,

    # раскрой/раскрыть → «раскр»
    "раскр": 0.4,

    # обойди/обойти → «обойт»
    "обойт": 0.35,

    "обойд": 0.35,

    # переопредели → «переопредел»
    "переопредел": 0.45,

    # взломай/взломать → «взлома»
    "взлома": 0.45,

    # вредоносный → «вредоносн»
    "вредоносн": 0.40,

    # запрещённый/запрещено → «запрещен»
    "запрещен": 0.30,

    # ограничение → «ограничен»
    "ограничен": 0.20,

    # цензура → «цензур»
    "цензур": 0.25,

    # секрет/секретный → «секрет»
    "секрет": 0.25,

    # пароль → «парол»
    "парол": 0.30,

    # системный → «систем» (низкий вес — частое легитимное слово)
    "системн": 0.2,

    "систему": 0.15,

    "защит": 0.2,

    "выполн": 0.1,

    "безопасн": 0.15,

    # ── Английские стеммы ──────────────────────────────────────────────────
    # ignore/ignored/ignoring → «ignor»
    "ignor": 0.45,

    # forget/forgetting → «forget»
    "forget": 0.35,

    "safety": 0.2,

    "rule": 0.15,

    # disregard → «disregard»
    "disregard": 0.45,

    # override → «overrid»
    "overrid": 0.50,

    # bypass → «bypass»
    "bypass": 0.45,

    # pretend → «pretend»
    "pretend": 0.35,

    # jailbreak → «jailbreak»
    "jailbreak": 0.75,

    # reveal → «reveal»
    "reveal": 0.35,

    # system → «system» (низкий вес)
    "system": 0.15,

    # hack → «hack»
    "hack": 0.40,

    # exploit → «exploit»
    "exploit": 0.45,

    # unrestricted → «unrestrict»
    "unrestrict": 0.55,

    # forbidden → «forbidden»
    "forbidden": 0.30,

    # secret → «secret»
    "secret": 0.25,

    "secur": 0.15,

    "set": 0.1,

    "model": 0.05,

    "danger": 0.05,

    "restrict": 0.1,

    "command": 0.05,

    # manipulate → «manipul»
    "manipul": 0.40,
}


# Невидимые и управляющие Unicode-символы, используемые для сокрытия инъекций.
INVISIBLE_RE = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f"  # zero-width chars
    r"\u202a-\u202e"  # directional overrides
    r"\u2060-\u2064"  # word joiner и др.
    r"\ufeff]"  # BOM
)

CYRILLIC_RE = re.compile(r"[а-яёА-ЯЁ]{4,}")
LATIN_RE = re.compile(r"[a-zA-Z]{4,}")
