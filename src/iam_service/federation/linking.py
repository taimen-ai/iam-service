from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam_service.federation.errors import FederationError
from iam_service.federation.verify import UpstreamClaims
from iam_service.models import (
    AuditEvent,
    ExternalIdentity,
    Group,
    GroupMember,
    IdentityProvider,
    OutboxEvent,
    Principal,
    TenantMembership,
)


@dataclass
class LinkedIdentity:
    principal: Principal
    identity: ExternalIdentity
    created: bool


async def link_identity(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: IdentityProvider,
    upstream: UpstreamClaims,
) -> LinkedIdentity:
    """Связывает upstream identity с Principal по `issuer + subject`.

    Стабильный external ID проверяется отдельно: он не даёт связать одну
    upstream identity с двумя Principals и ловит рассинхронизацию, когда IdP
    пересоздал пользователя из LDAP.
    """

    by_subject = await session.scalar(
        select(ExternalIdentity).where(
            ExternalIdentity.issuer == provider.issuer,
            ExternalIdentity.subject == upstream.subject,
        )
    )
    by_external_id = await session.scalar(
        select(ExternalIdentity).where(
            ExternalIdentity.identity_provider_id == provider.id,
            ExternalIdentity.external_id == upstream.external_id,
        )
    )
    if by_subject is not None and by_external_id is not None and by_subject.id != by_external_id.id:
        raise FederationError("external_identity_conflict", status_code=409)

    identity = by_subject or by_external_id
    if identity is None:
        principal = Principal(kind="human", display_name=_display_name(provider, upstream))
        session.add(principal)
        await session.flush()
        session.add(TenantMembership(tenant_id=tenant_id, principal_id=principal.id))
        identity = ExternalIdentity(
            principal_id=principal.id,
            identity_provider_id=provider.id,
            issuer=provider.issuer,
            subject=upstream.subject,
            external_id=upstream.external_id,
            source="federated",
        )
        session.add(identity)
        await session.flush()
        session.add(
            OutboxEvent(
                tenant_id=tenant_id,
                type="principal.created",
                aggregate_type="principal",
                aggregate_id=principal.id,
                payload={
                    "principalId": str(principal.id),
                    "kind": principal.kind,
                    "identityProvider": provider.key,
                },
            )
        )
        session.add(
            OutboxEvent(
                tenant_id=tenant_id,
                type="external_identity.linked",
                aggregate_type="external_identity",
                aggregate_id=identity.id,
                payload={
                    "externalIdentityId": str(identity.id),
                    "principalId": str(principal.id),
                    "identityProvider": provider.key,
                },
            )
        )
        return LinkedIdentity(principal=principal, identity=identity, created=True)

    if identity.status != "active":
        raise FederationError("identity_disabled", status_code=403)
    if by_subject is not None and by_subject.external_id not in (None, upstream.external_id):
        raise FederationError("external_identity_conflict", status_code=409)

    principal = await session.get(Principal, identity.principal_id)
    if principal is None or principal.status != "active":
        raise FederationError("principal_disabled", status_code=403)
    membership = await session.get(
        TenantMembership, {"tenant_id": tenant_id, "principal_id": principal.id}
    )
    if membership is None or membership.status != "active":
        raise FederationError("principal_not_in_tenant", status_code=403)

    if identity.identity_provider_id is None:
        identity.identity_provider_id = provider.id
        identity.source = "federated"
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action="federation.identity_adopted",
                actor_ref=str(principal.id),
                resource_type="external_identity",
                resource_id=identity.id,
                outcome="allowed",
                reason=f"provider:{provider.key}",
            )
        )
    if identity.external_id is None:
        identity.external_id = upstream.external_id
    if identity.subject != upstream.subject:
        identity.subject = upstream.subject
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action="federation.subject_rotated",
                actor_ref=str(principal.id),
                resource_type="external_identity",
                resource_id=identity.id,
                outcome="allowed",
                reason=f"provider:{provider.key}",
            )
        )
    return LinkedIdentity(principal=principal, identity=identity, created=False)


async def reconcile_group_projection(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: IdentityProvider,
    principal_id: uuid.UUID,
    group_keys: Sequence[str],
) -> list[str]:
    """Приводит federated членства провайдера к текущему состоянию токена.

    Локальные членства и членства других провайдеров не трогаются: удаление
    upstream-группы отзывает только то, что породила эта federation.
    """

    desired = sorted(set(group_keys))
    groups = {
        group.key: group
        for group in await session.scalars(
            select(Group).where(Group.tenant_id == tenant_id, Group.key.in_(desired))
        )
    }
    for key in desired:
        if key in groups:
            continue
        group = Group(
            tenant_id=tenant_id,
            key=key,
            name=key,
            source="federated",
            identity_provider_id=provider.id,
        )
        session.add(group)
        await session.flush()
        groups[key] = group
        session.add(
            OutboxEvent(
                tenant_id=tenant_id,
                type="group.created",
                aggregate_type="group",
                aggregate_id=group.id,
                payload={
                    "groupId": str(group.id),
                    "key": group.key,
                    "source": "federated",
                    "identityProvider": provider.key,
                },
            )
        )

    existing = list(
        await session.scalars(
            select(GroupMember).where(
                GroupMember.tenant_id == tenant_id,
                GroupMember.principal_id == principal_id,
                GroupMember.source == "federated",
                GroupMember.identity_provider_id == provider.id,
            )
        )
    )
    desired_group_ids = {groups[key].id for key in desired}
    for member in existing:
        if member.group_id in desired_group_ids:
            continue
        await session.delete(member)
        session.add(
            OutboxEvent(
                tenant_id=tenant_id,
                type="group_membership.removed",
                aggregate_type="group",
                aggregate_id=member.group_id,
                payload={
                    "groupId": str(member.group_id),
                    "principalId": str(principal_id),
                    "identityProvider": provider.key,
                },
            )
        )

    already_member = {member.group_id for member in existing}
    for key in desired:
        group = groups[key]
        if group.id in already_member:
            continue
        session.add(
            GroupMember(
                tenant_id=tenant_id,
                group_id=group.id,
                principal_id=principal_id,
                source="federated",
                identity_provider_id=provider.id,
            )
        )
        session.add(
            OutboxEvent(
                tenant_id=tenant_id,
                type="group_membership.added",
                aggregate_type="group",
                aggregate_id=group.id,
                payload={
                    "groupId": str(group.id),
                    "principalId": str(principal_id),
                    "identityProvider": provider.key,
                },
            )
        )
    return desired


def touch_authentication(identity: ExternalIdentity, *, acr: str | None) -> None:
    identity.last_authenticated_at = datetime.now(UTC)
    identity.last_acr = acr


def _display_name(provider: IdentityProvider, upstream: UpstreamClaims) -> str:
    return f"{provider.key}:{upstream.external_id}"[:200]
