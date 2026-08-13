"""Таблицы provisioning source и SCIM-проекции.

Модели живут отдельно, но регистрируются в общем `Base`, поэтому alembic и
`create_all` видят их вместе с остальным IAM. Внутренним identity key остаётся
Principal и `issuer + subject`; SCIM `id`, `externalId` и `userName` — это
атрибуты внешней population, а не замена identity.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
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

KIND_SCIM = "scim"
KIND_LDAP = "ldap"

UPSTREAM_OFF = "off"
UPSTREAM_SCIM = "scim"
UPSTREAM_ADMIN = "admin"
UPSTREAM_AUTO = "auto"


class ProvisioningSource(Base):
    """Единственный authoritative источник lifecycle для одной population.

    Population — это конкретный upstream identity provider. Уникальность
    `(tenant_id, identity_provider_id)` физически запрещает одновременную запись
    SCIM и LDAP в одну population: второй источник просто не регистрируется.
    `service_principal_id` — confidential service identity SCIM-клиента; она
    определяет source по предъявленному token и никогда не принадлежит человеку.
    """

    __tablename__ = "provisioning_sources"
    __table_args__ = (
        UniqueConstraint("tenant_id", "key", name="uq_provisioning_sources_tenant_key"),
        UniqueConstraint(
            "tenant_id", "identity_provider_id", name="uq_provisioning_sources_population"
        ),
        UniqueConstraint("service_principal_id", name="uq_provisioning_sources_service_principal"),
        CheckConstraint("kind IN ('scim', 'ldap')", name="kind"),
        CheckConstraint("status IN ('active', 'disabled')", name="status"),
        CheckConstraint(
            "upstream_mode IN ('off', 'scim', 'admin', 'auto')", name="upstream_mode"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id"))
    key: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(20), default=KIND_SCIM)
    identity_provider_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("identity_providers.id")
    )
    service_principal_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("principals.id"), nullable=True
    )
    # Драйвер записи в upstream: `off` оставляет только проекцию IAM, `auto`
    # пробует SCIM API Keycloak и падает обратно на стабильный Admin API.
    upstream_mode: Mapped[str] = mapped_column(String(20), default=UPSTREAM_OFF)
    upstream_base_url: Mapped[str] = mapped_column(String(500), default="")
    upstream_realm: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(String(20), default="active")
    stale_after_seconds: Mapped[int] = mapped_column(default=86400)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stale_alerted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScimUser(Base):
    """Проекция SCIM `User` на Principal и external identity.

    `external_id` — стабильный идентификатор из authoritative source; именно он,
    а не `user_name`, связывает запись с upstream. Уникальность обоих полей в
    пределах source делает повтор create безопасным.
    """

    __tablename__ = "scim_users"
    __table_args__ = (
        UniqueConstraint(
            "provisioning_source_id", "external_id", name="uq_scim_users_source_external_id"
        ),
        UniqueConstraint(
            "provisioning_source_id", "user_name", name="uq_scim_users_source_user_name"
        ),
        UniqueConstraint("principal_id", name="uq_scim_users_principal"),
        Index("ix_scim_users_tenant", "tenant_id", "provisioning_source_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id"))
    provisioning_source_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("provisioning_sources.id")
    )
    external_id: Mapped[str] = mapped_column(String(500))
    user_name: Mapped[str] = mapped_column(String(320))
    display_name: Mapped[str] = mapped_column(String(200), default="")
    principal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("principals.id"))
    external_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("external_identities.id"), nullable=True
    )
    upstream_user_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScimGroup(Base):
    """Проекция SCIM `Group` на глобальную IAM Group."""

    __tablename__ = "scim_groups"
    __table_args__ = (
        UniqueConstraint(
            "provisioning_source_id", "external_id", name="uq_scim_groups_source_external_id"
        ),
        UniqueConstraint(
            "provisioning_source_id", "display_name", name="uq_scim_groups_source_display_name"
        ),
        UniqueConstraint("group_id", name="uq_scim_groups_group"),
        Index("ix_scim_groups_tenant", "tenant_id", "provisioning_source_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id"))
    provisioning_source_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("provisioning_sources.id")
    )
    external_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    display_name: Mapped[str] = mapped_column(String(200))
    group_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("groups.id"))
    version: Mapped[int] = mapped_column(default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
