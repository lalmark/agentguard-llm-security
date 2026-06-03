from . import (
    STEM_BLOCKLIST,
    INVISIBLE_RE,
    DELIMITER_PATTERNS,
    PHRASE_PATTERNS,
    normalize,
    tokenize,
    detect_lang_switch,
    stem_en,
    stem_ru,
    GuardResult
)


class InputFilter:
    """
    Детерминированный фильтр входных запросов пользователя.

    Принимает запрос пользователя ДО его передачи в LLM и возвращает
    решение о допустимости запроса на основе суммарного балла риска.

    Параметры
    ----------
    threshold : float
        Порог суммарного балла риска для блокировки [0.0 … 1.0].
        По умолчанию 0.60.
    extra_stems : dict | None
        Дополнительные пользовательские стеммы и их веса.
        Объединяются с базовым STEM_BLOCKLIST.
    """

    def __init__(
            self,
            threshold: float = 0.60,
            extra_stems = None,
    ) -> None:
        self.threshold = threshold
        self._stems = {
            **STEM_BLOCKLIST,
            **(extra_stems or {}),
        }

    def check(self, user_input: str):
        """
        Проверяет запрос пользователя.

        Алгоритм
        --------
        1. Проверка невидимых символов на RAW тексте (до нормализации)
        2. Нормализация текста (NFKC + удаление невидимых)
        3. Стемминг-детекция по токенам
        4. Паттерн-детекция разделителей
        5. Паттерн-детекция фраз
        6. Детект смены языка
        7. Решение по порогу
        """
        score = 0.0
        triggered = []
        details = []

        # ── 1. Невидимые символы (до нормализации) ───────────────────────────
        if INVISIBLE_RE.search(user_input):
            invisible_score = 0.65
            score += invisible_score
            triggered.append("invisible_chars")
            details.append(
                f"Невидимые управляющие символы Unicode (вес={invisible_score})"
            )

        # ── 2. Нормализация ───────────────────────────────────────────────────
        normalized = normalize(user_input)

        # ── 3. Стемминг-детекция ─────────────────────────────────────────────
        tokens = tokenize(normalized)
        matched = {}

        for token in tokens:
            for stem_fn in (stem_ru, stem_en):
                stem = stem_fn(token)
                if stem in self._stems and stem not in matched:
                    matched[stem] = self._stems[stem]

        for stem, weight in matched.items():
            score += weight
            triggered.append(f"stem:{stem}")
            details.append(
                f"Корень вредоносного слова: «{stem}» (вес={weight})"
            )

        # ── 4. Паттерн-детекция разделителей ─────────────────────────────────
        for pattern, weight, rule in DELIMITER_PATTERNS:
            if pattern.search(normalized):
                score += weight
                triggered.append(rule)
                details.append(
                    f"Псевдо-системный разделитель: {rule} (вес={weight})"
                )

        # ── 5. Паттерн-детекция фраз ─────────────────────────────────────────
        for pattern, weight, rule in PHRASE_PATTERNS:
            if pattern.search(normalized):
                score += weight
                triggered.append(rule)
                details.append(
                    f"Вредоносная конструкция: {rule} (вес={weight})"
                )

        # ── 6. Смена языка ────────────────────────────────────────────────────
        lang = detect_lang_switch(normalized)
        if lang:
            lang_score, lang_info = lang
            score += lang_score
            triggered.append("lang_switch")
            details.append(
                f"Смена языка в запросе: {lang_info} (вес={lang_score})"
            )

        # ── 7. Решение ────────────────────────────────────────────────────────
        score = min(round(score, 3), 1.0)
        allowed = score < self.threshold

        return GuardResult(
            allowed=allowed,
            triggered_rules=triggered,
            risk_score=score,
            details=details,
        )
    