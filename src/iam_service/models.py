from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'disabled')", name="tenant_status"),
        Index("ix_tenants_created", "created_at", "id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(80), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Principal(Base):
    __tablename__ = "principals"
    __table_args__ = (
        CheckConstraint("kind IN ('human', 'agent', 'service_account', 'workload')", name="kind"),
        CheckConstraint("status IN ('active', 'paused', 'disabled')", name="status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(30))
    display_name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TenantMembership(Base):
    __tablename__ = "tenant_memberships"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'disabled')", name="status"),
        Index("ix_tenant_memberships_principal", "principal_id", "tenant_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id"), primary_key=True)
    principal_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("principals.id"), primary_key=True
    )
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IdentityProvider(Base):
    """Upstream OIDC issuer (Keycloak reference deployment или совместимый IdP).

    IAM хранит только non-secret конфигурацию доверия: issuer, audience, набор
    claim names и allowlist групп. Пароли, client secrets и LDAP bind credentials
    остаются в deployment environment самого IdP.
    """

    __tablename__ = "identity_providers"
    __table_args__ = (
        UniqueConstraint("tenant_id", "key", name="uq_identity_providers_tenant_key"),
        UniqueConstraint("tenant_id", "issuer", name="uq_identity_providers_tenant_issuer"),
        CheckConstraint("status IN ('active', 'disabled')", name="status"),
        CheckConstraint("lifecycle_profile IN ('read_only', 'managed')", name="lifecycle_profile"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id"))
    key: Mapped[str] = mapped_column(String(120))
    issuer: Mapped[str] = mapped_column(String(500))
    audience: Mapped[str] = mapped_column(String(200))
    jwks_uri: Mapped[str] = mapped_column(String(500), default="")
    subject_claim: Mapped[str] = mapped_column(String(80), default="sub")
    external_id_claim: Mapped[str] = mapped_column(String(80), default="sub")
    group_claim: Mapped[str] = mapped_column(String(80), default="groups")
    group_mappings: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    required_acr_values: Mapped[list[str]] = mapped_column(JSON, default=list)
    required_amr_values: Mapped[list[str]] = mapped_column(JSON, default=list)
    lifecycle_profile: Mapped[str] = mapped_column(String(20), default="read_only")
    jwks_cache_ttl_seconds: Mapped[int] = mapped_column(default=300)
    jwks_stale_grace_seconds: Mapped[int] = mapped_column(default=900)
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExternalIdentity(Base):
    __tablename__ = "external_identities"
    __table_args__ = (
        UniqueConstraint("issuer", "subject", name="uq_external_identities_issuer_subject"),
        UniqueConstraint(
            "identity_provider_id",
            "external_id",
            name="uq_external_identities_provider_external_id",
        ),
        CheckConstraint("status IN ('active', 'disabled')", name="status"),
        CheckConstraint("source IN ('manual', 'federated')", name="source"),
        Index("ix_external_identities_principal", "principal_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    principal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("principals.id"))
    identity_provider_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("identity_providers.id"), nullable=True
    )
    issuer: Mapped[str] = mapped_column(String(500))
    subject: Mapped[str] = mapped_column(String(500))
    external_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    source: Mapped[str] = mapped_column(String(20), default="manual")
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_authenticated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_acr: Mapped[str | None] = mapped_column(String(200), nullable=True)


class Audience(Base):
    __tablename__ = "audiences"
    __table_args__ = (
        UniqueConstraint("tenant_id", "key", name="uq_audiences_tenant_key"),
        CheckConstraint("status IN ('active', 'disabled')", name="status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id"))
    key: Mapped[str] = mapped_column(String(120))
    allowed_scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ServiceAccount(Base):
    __tablename__ = "service_accounts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "principal_id", name="uq_service_accounts_principal"),
        Index("ix_service_accounts_tenant", "tenant_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id"))
    principal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("principals.id"))
    client_id: Mapped[str] = mapped_column(String(120), unique=True)
    secret_hash: Mapped[str] = mapped_column(Text)
    audiences: Mapped[list[str]] = mapped_column(JSON, default=list)
    scope_ceiling: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Group(Base):
    __tablename__ = "groups"
    __table_args__ = (
        UniqueConstraint("tenant_id", "key", name="uq_groups_tenant_key"),
        UniqueConstraint("tenant_id", "id", name="uq_groups_tenant_id"),
        CheckConstraint("status IN ('active', 'disabled')", name="status"),
        CheckConstraint("source IN ('local', 'federated')", name="source"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id"))
    key: Mapped[str] = mapped_column(String(120))
    name: Mapped[str] = mapped_column(String(200))
    source: Mapped[str] = mapped_column(String(20), default="local")
    identity_provider_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("identity_providers.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GroupMember(Base):
    __tablename__ = "group_members"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "group_id"],
            ["groups.tenant_id", "groups.id"],
            name="fk_group_members_group",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "principal_id"],
            ["tenant_memberships.tenant_id", "tenant_memberships.principal_id"],
            name="fk_group_members_membership",
        ),
        UniqueConstraint("group_id", "principal_id", name="uq_group_members_entry"),
        CheckConstraint("source IN ('local', 'federated')", name="source"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    group_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    principal_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    source: Mapped[str] = mapped_column(String(20), default="local")
    identity_provider_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("identity_providers.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OutboxEvent(Base):
    __tablename__ = "outbox_events"
    __table_args__ = (Index("ix_outbox_events_sequence", "sequence"),)

    sequence: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id"))
    type: Mapped[str] = mapped_column(String(120))
    aggregate_type: Mapped[str] = mapped_column(String(80))
    aggregate_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id"))
    action: Mapped[str] = mapped_column(String(120))
    actor_ref: Mapped[str] = mapped_column(String(200))
    resource_type: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    outcome: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(Text, default="")
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
