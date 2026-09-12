"""Контракты управления provisioning sources.

Регистрация источника — административная операция, поэтому она использует
обычные схемы IAM, а не SCIM-представления.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from iam_service.scim.models import ProvisioningSource


class ProvisioningSourceCreate(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,118}[a-z0-9]$")
    kind: str = Field(default="scim", pattern=r"^(scim|ldap)$")
    identity_provider: str = Field(alias="identityProvider", min_length=1, max_length=120)
    service_principal_id: uuid.UUID | None = Field(alias="servicePrincipalId", default=None)
    upstream_mode: str = Field(
        alias="upstreamMode", default="off", pattern=r"^(off|scim|admin|auto)$"
    )
    upstream_base_url: str = Field(alias="upstreamBaseUrl", default="", max_length=500)
    upstream_realm: str = Field(alias="upstreamRealm", default="", max_length=120)
    stale_after_seconds: int = Field(alias="staleAfterSeconds", default=86400, ge=60, le=2592000)

    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class ProvisioningSourceView(BaseModel):
    id: uuid.UUID
    key: str
    kind: str
    identity_provider_id: uuid.UUID = Field(alias="identityProviderId")
    service_principal_id: uuid.UUID | None = Field(alias="servicePrincipalId")
    upstream_mode: str = Field(alias="upstreamMode")
    status: str
    stale_after_seconds: int = Field(alias="staleAfterSeconds")
    last_sync_at: datetime | None = Field(alias="lastSyncAt")
    stale: bool

    model_config = ConfigDict(populate_by_name=True)


def source_view(source: ProvisioningSource, *, now: datetime) -> ProvisioningSourceView:
    """Отдать состояние источника вместе с признаком устаревания.

    Источник, который ещё ни разу не синхронизировался, считается устаревшим
    по возрасту самой регистрации: тихо неработающая интеграция должна быть
    заметна сразу, а не после первой удачной записи.
    """

    reference = _aware(source.last_sync_at) or _aware(source.created_at) or now
    stale = (now - reference).total_seconds() > source.stale_after_seconds
    return ProvisioningSourceView(
        id=source.id,
        key=source.key,
        kind=source.kind,
        identityProviderId=source.identity_provider_id,
        servicePrincipalId=source.service_principal_id,
        upstreamMode=source.upstream_mode,
        status=source.status,
        staleAfterSeconds=source.stale_after_seconds,
        lastSyncAt=_aware(source.last_sync_at),
        stale=stale and source.status == "active",
    )


def _aware(value: datetime | None) -> datetime | None:
    """SQLite отдаёт naive datetime; сравнения ведём в UTC."""

    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
