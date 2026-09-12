"""Разбор SCIM-фильтров (RFC 7644 §3.4.2.2).

Поддерживается ровно то, что нужно reconciliation: сравнение `eq` по
идентификаторам population, объединённое через `and`. Всё остальное — включая
`or`, скобочные группы и подстановочные операторы — отклоняется как
`invalidFilter`, а не молча игнорируется: тихо расширенная выборка опаснее
явного отказа.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from iam_service.scim.errors import ScimFault

_TERM = re.compile(
    r"^(?P<attribute>[A-Za-z][A-Za-z0-9_.]*)\s+(?P<operator>[A-Za-z]{2})\s+(?P<value>.+)$"
)


@dataclass(frozen=True)
class FilterTerm:
    attribute: str
    value: str | bool


def parse_filter(expression: str, *, allowed: dict[str, str]) -> list[FilterTerm]:
    """Вернуть AND-термы фильтра, приведённые к внутренним именам атрибутов."""

    terms: list[FilterTerm] = []
    for raw in re.split(r"\s+and\s+", expression.strip(), flags=re.IGNORECASE):
        match = _TERM.match(raw.strip())
        if match is None:
            raise ScimFault(400, f"unsupported filter: {expression}", scim_type="invalidFilter")
        attribute = match.group("attribute")
        if match.group("operator").lower() != "eq":
            raise ScimFault(400, "only the eq operator is supported", scim_type="invalidFilter")
        if attribute not in allowed:
            raise ScimFault(
                400, f"attribute {attribute} is not filterable", scim_type="invalidFilter"
            )
        terms.append(FilterTerm(attribute=allowed[attribute], value=_value(match.group("value"))))
    if not terms:
        raise ScimFault(400, "empty filter", scim_type="invalidFilter")
    return terms


def _value(raw: str) -> str | bool:
    token = raw.strip()
    if token.startswith('"') and token.endswith('"') and len(token) >= 2:
        return token[1:-1]
    lowered = token.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    raise ScimFault(
        400, "filter value must be a quoted string or boolean", scim_type="invalidFilter"
    )
