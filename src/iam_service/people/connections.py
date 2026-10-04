"""Issuer identity подключения: `connection:<tenantId>:<connectionKey>` (ADR-0004, п. 3).

Identity подключения — пользователь подключённой внешней системы,
сопоставленный с человеком. Входа она не даёт: ни один путь выпуска token её
не принимает, а префикс `connection:` зарезервирован — issuer identity
provider обязан быть URL (`invalid_issuer`).
"""

from __future__ import annotations

import re
import uuid

CONNECTION_SOURCE = "connection"
CONNECTION_ISSUER_PREFIX = "connection:"

# Tenant — UUID в каноническом виде; ключ — форма ключа `Connection` ядра
# (CP-ADR-0079), без `:` — это разделитель issuer.
_CONNECTION_ISSUER = re.compile(
    r"^connection:"
    r"(?P<tenant>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r":(?P<key>[a-z0-9._-]{1,200})$"
)


def is_connection_issuer(issuer: str) -> bool:
    """Issuer из пространства имён подключений — любой формы."""

    return issuer.startswith(CONNECTION_ISSUER_PREFIX)


def tenant_connection_prefix(tenant_id: uuid.UUID) -> str:
    """Префикс issuer подключений tenant'а: `connection:<tenantId>:`."""

    return f"{CONNECTION_ISSUER_PREFIX}{tenant_id}:"


def connection_issuer_tenant(issuer: str) -> uuid.UUID | None:
    """Tenant корректного issuer подключения; `None`, если форма иная."""

    match = _CONNECTION_ISSUER.fullmatch(issuer)
    return uuid.UUID(match["tenant"]) if match else None
