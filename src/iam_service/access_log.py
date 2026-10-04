"""Фильтр access log uvicorn: адрес поиска по почте не попадает в журнал.

`GET …/principals:by-email?email=` несёт адрес в query string (ADR-0004,
п. 2), а uvicorn пишет строку запроса целиком. Фильтр логгера
`uvicorn.access` заменяет значение параметра `email` на `[redacted]`.

Имя параметра сравнивается после декодирования, как его видит маршрут:
`?e%6Dail=…` доходит до FastAPI как `email`, и такой адрес тоже вырезается.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import parse_qsl

ACCESS_LOGGER = "uvicorn.access"
REDACTED = "[redacted]"

REDACTED_NAME = "email"

# Query string: после `?` до `#` или пробела (конец цели запроса в тексте записи).
_QUERY = re.compile(r"\?([^\s#]*)")


def _redact_pair(pair: str) -> str:
    # Starlette разбирает query string тем же `parse_qsl`: имя декодируется
    # (`%XX`, `+`) так же, как его увидит маршрут.
    name, sep, _ = pair.partition("=")
    parsed = parse_qsl(pair, keep_blank_values=True)
    if sep and parsed and parsed[0][0].lower() == REDACTED_NAME:
        return f"{name}={REDACTED}"
    return pair


def _redact_match(match: re.Match[str]) -> str:
    return "?" + "&".join(_redact_pair(pair) for pair in match.group(1).split("&"))


def redact_query(value: str) -> str:
    return _QUERY.sub(_redact_match, value)


class EmailRedactingFilter(logging.Filter):
    """Переписывает аргументы записи uvicorn.access, не отбрасывая её.

    Uvicorn передаёт путь с query string отдельным аргументом записи
    (`client, method, path, http_version, status`), и его форматтер
    распаковывает кортеж, поэтому заменяется элемент, а не весь текст.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(
                redact_query(arg) if isinstance(arg, str) else arg for arg in record.args
            )
        elif isinstance(record.msg, str):
            record.msg = redact_query(record.msg)
        return True


def install_access_log_filter() -> None:
    """Повесить фильтр на логгер `uvicorn.access` один раз на процесс."""

    logger = logging.getLogger(ACCESS_LOGGER)
    if not any(isinstance(item, EmailRedactingFilter) for item in logger.filters):
        logger.addFilter(EmailRedactingFilter())
