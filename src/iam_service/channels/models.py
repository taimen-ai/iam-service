"""Таблицы каналов как способа входа: провайдер per tenant и код привязки.

Сама привязка аккаунта канала — обычная `ExternalIdentity` с `source =
'channel'`: у неё тот же жизненный цикл (active/disabled), и её id служит
`credential_id` выданных по ней токенов.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from iam_service.models import Base, utcnow

# Каналы, которые IAM умеет принимать как способ входа. Список закрыт:
# новый канал — это новое решение о доверии, а не строка конфигурации.
CHANNELS = ("telegram",)


class ChannelProvider(Base):
    """Канал, включённый в tenant как провайдер внешней identity.

    Отсутствие записи и `disabled` значат одно и то же — вход через канал
    закрыт. Секретов канала (токена бота) IAM не хранит: доверие к каналу
    выражено service account его адаптера со scope `iam:channel-links`.
    """

    __tablename__ = "channel_providers"
    __table_args__ = (
        UniqueConstraint("tenant_id", "channel", name="uq_channel_providers_tenant_channel"),
        CheckConstraint("channel IN ('telegram')", name="channel"),
        CheckConstraint("status IN ('active', 'disabled')", name="status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id"))
    channel: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ChannelLinkIntent(Base):
    """Одноразовый код привязки аккаунта канала к Principal.

    Хранится только SHA-256 кода; сам код показывается человеку один раз.
    Код живёт `channel_link_code_ttl_seconds` и гасится первым успешным
    подтверждением (`used_at`).
    """

    __tablename__ = "channel_link_intents"
    __table_args__ = (
        UniqueConstraint("code_hash", name="uq_channel_link_intents_code_hash"),
        CheckConstraint("channel IN ('telegram')", name="channel"),
        Index("ix_channel_link_intents_principal", "tenant_id", "principal_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id"))
    principal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("principals.id"))
    channel: Mapped[str] = mapped_column(String(40))
    code_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    external_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("external_identities.id"), nullable=True
    )
