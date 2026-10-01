"""Привилегированные scope: выдаются только члену группы и по явному запросу.

Реестр — `Settings.privileged_scope_groups()`: scope → ключ группы tenant'а,
члену которой federation выдаёт этот scope (ADR-0003). Группа — только
заведённая bootstrap (`source = local`) и активная: federation-проекция и SCIM
группу с таким ключом не создают, а созданная ими раньше права не даёт.
Членство — любого источника (local, federated, scim): federation-вход приводит
его к группам IdP до выпуска token.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection, Mapping

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from iam_service.models import Group, GroupMember


async def member_groups(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    principal_id: uuid.UUID,
    group_keys: Collection[str],
) -> set[str]:
    """Ключи из `group_keys`, в чьих активных bootstrap-группах состоит Principal."""

    if not group_keys:
        return set()
    rows = await session.scalars(
        select(Group.key)
        .join(GroupMember, GroupMember.group_id == Group.id)
        .where(
            Group.tenant_id == tenant_id,
            Group.key.in_(sorted(set(group_keys))),
            Group.source == "local",
            Group.status == "active",
            GroupMember.tenant_id == tenant_id,
            GroupMember.principal_id == principal_id,
        )
    )
    return set(rows)


async def is_group_member(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    principal_id: uuid.UUID,
    group_key: str,
) -> bool:
    return bool(
        await member_groups(
            session, tenant_id=tenant_id, principal_id=principal_id, group_keys=[group_key]
        )
    )


async def entitled_privileged_scopes(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    principal_id: uuid.UUID,
    scopes: Collection[str],
    privileged: Mapping[str, str],
) -> set[str]:
    """Привилегированные scope из `scopes`, которые Principal может получить."""

    candidates = {scope: privileged[scope] for scope in scopes if scope in privileged}
    groups = await member_groups(
        session,
        tenant_id=tenant_id,
        principal_id=principal_id,
        group_keys=set(candidates.values()),
    )
    return {scope for scope, group in candidates.items() if group in groups}
