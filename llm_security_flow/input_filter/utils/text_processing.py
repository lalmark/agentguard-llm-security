from .patterns import CYRILLIC_RE, LATIN_RE, INVISIBLE_RE
import unicodedata
import re


def detect_lang_switch(text: str):
    """
    Обнаруживает резкую смену языка внутри одного запроса.
    Возвращает (score, detail) или None.
    """
    cyr = CYRILLIC_RE.findall(text)
    lat = LATIN_RE.findall(text)
    if not (cyr and lat):
        return None

    cyr_len = sum(len(b) for b in cyr)
    lat_len = sum(len(b) for b in lat)
    total = cyr_len + lat_len
    minority_ratio = min(cyr_len, lat_len) / total if total else 0

    # Смена языка значима, если меньший блок > 15% всего текста
    if minority_ratio > 0.15:
        return (0.30, f"ratio={minority_ratio:.2f}")
    return None


def normalize(text: str):
    """
    Нормализация текста:
    1. Unicode NFKC — устраняет визуально-идентичные символы
    2. Удаление невидимых управляющих символов
    3. Схлопывание пробелов
    """
    text = unicodedata.normalize("NFKC", text)
    text = INVISIBLE_RE.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def tokenize(text: str):
    """Токенизация: буквенные последовательности длиной ≥ 3 символа."""
    return re.findall(r"[а-яёА-ЯЁa-zA-Z]{3,}", text)