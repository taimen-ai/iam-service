"""Почта как ключ поиска человека (ADR-0004, п. 1–2).

Одно правило нормализации для записи почты при federation-входе и для
параметра поиска: иначе адрес, записанный одним способом, не находился бы
запросом, записанным другим.
"""

from __future__ import annotations

EMAIL_MAX_LENGTH = 320


def normalize_email(value: object) -> str | None:
    """Нормализованный адрес или `None`, если адрес некорректен.

    Пробелы по краям срезаются, адрес целиком приводится к нижнему регистру;
    ровно один `@`, непустые части, длина не больше 320.
    """

    if not isinstance(value, str):
        return None
    email = value.strip().lower()
    if len(email) > EMAIL_MAX_LENGTH or email.count("@") != 1:
        return None
    local, _, domain = email.partition("@")
    if not local or not domain:
        return None
    return email
