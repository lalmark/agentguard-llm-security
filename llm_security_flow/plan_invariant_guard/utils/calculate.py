from .patterns import STOP_WORDS
import re
from collections import Counter
import hashlib
import math


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────
def tokenize(text: str) -> list[str]:
    """Нормализует текст, возвращает список значимых токенов без стоп-слов."""
    tokens = re.findall(r"[a-zа-яё]+", text.lower())
    return [t for t in tokens if t not in STOP_WORDS and len(t) > 2]


def cosine_similarity(a: list[str], b: list[str]) -> float:
    """Косинусное сходство двух токенизированных текстов (bag-of-words)."""
    if not a or not b:
        return 0.0
    ca, cb = Counter(a), Counter(b)
    dot = sum(ca[t] * cb[t] for t in ca if t in cb)
    mag_a = math.sqrt(sum(v * v for v in ca.values()))
    mag_b = math.sqrt(sum(v * v for v in cb.values()))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


def hash_plan(goal: str, steps: list[str]) -> str:
    """SHA-256 хеш плана (goal + шаги)."""
    payload = goal.strip() + "\n" + "\n".join(s.strip() for s in steps)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
