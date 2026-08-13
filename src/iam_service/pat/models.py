"""Таблицы Platform Access Token и снимка human authentication.

Модели живут в отдельном модуле, но регистрируются в общем `Base`, поэтому
alembic autogenerate и `create_all` видят их вместе с остальным IAM.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from iam_service.models import Base, utcnow


class AuthenticationContext(Base):
    """Подтверждённый факт human authentication, пригодный для выпуска PAT.

    Запись авторитетна и создаётся сервером: свежесть считается по
    `recorded_at` (серверные часы), а `auth_time`, `acr` и `amr` — снимок
    upstream-контекста. Штатный производитель записи — federation-вход;
    административный endpoint существует для bootstrap и эксплуатации.
    Хранится только issuer и параметры входа, без email, username и DN.
    """

    __tablename__ = "authentication_contexts"
    __table_args__ = (
        CheckConstraint("source IN ('federation', 'bootstrap')", name="source"),
        Index("ix_authentication_contexts_principal", "tenant_id", "principal_id", "recorded_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id"))
    principal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("principals.id"))
    external_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("external_identities.id"), nullable=True
    )
    issuer: Mapped[str] = mapped_column(String(500))
    acr: Mapped[str | None] = mapped_column(String(200), nullable=True)
    amr: Mapped[list[str]] = mapped_column(JSON, default=list)
    auth_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source: Mapped[str] = mapped_column(String(40), default="federation")


class PlatformAccessToken(Base):
    """Principal-bound credential, предъявляемый только IAM.

    Хранится lookup prefix и hash секрета; `authentication_context` — снимок
    human authentication на момент выпуска, без PII сверх acr/amr/auth_time.
    `scope_ceiling` ограничивает authority и никогда её не расширяет.
    """

    __tablename__ = "platform_access_tokens"
    __table_args__ = (
        UniqueConstraint("public_prefix", name="uq_platform_access_tokens_prefix"),
        UniqueConstraint("secret_hash", name="uq_platform_access_tokens_secret_hash"),
        UniqueConstraint(
            "tenant_id", "idempotency_key", name="uq_platform_access_tokens_idempotency"
        ),
        CheckConstraint(
            "kind IN ('platform_access_token', 'legacy_control_plane_api_key')", name="kind"
        ),
        Index("ix_platform_access_tokens_principal", "tenant_id", "principal_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id"))
    principal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("principals.id"))
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(40), default="platform_access_token")
    public_prefix: Mapped[str] = mapped_column(String(64))
    secret_hash: Mapped[str] = mapped_column(String(128))
    audiences: Mapped[list[str]] = mapped_column(JSON, default=list)
    scope_ceiling: Mapped[list[str]] = mapped_column(JSON, default=list)
    authentication_context: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    idempotency_key: Mapped[str | None] = mapped_column(String(200), nullable=True)
    rotated_from_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("platform_access_tokens.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    revoke_reason: Mapped[str] = mapped_column(Text, default="")
