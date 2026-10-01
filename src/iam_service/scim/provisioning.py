"""Логика Identity Provisioning Adapter.

Provisioning создаёт и отключает identity и глобальные группы. Он не выдаёт
Product Entitlement и не создаёт service-local grants: доступ к ресурсу
по-прежнему требует отдельных решений entitlement-service и domain policy
конкретного продукта (ADR-0013).
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Collection
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

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
from iam_service.pat.routes import mark_principal_enabled, revoke_tokens_for_principal
from iam_service.scim.driver import UpstreamUnavailable
from iam_service.scim.errors import ScimFault
from iam_service.scim.filters import FilterTerm
from iam_service.scim.models import ProvisioningSource, ScimGroup, ScimUser
from iam_service.scim.schemas import (
    ScimGroupRequest,
    ScimPatchOperation,
    ScimUserRequest,
    etag,
)

SOURCE_PROVISIONED = "scim"
IDENTITY_SOURCE_PROVISIONED = "provisioned"

USER_FILTER_ATTRIBUTES = {
    "userName": "user_name",
    "externalId": "external_id",
    "displayName": "display_name",
    "active": "active",
    "id": "id",
}
GROUP_FILTER_ATTRIBUTES = {
    "displayName": "display_name",
    "externalId": "external_id",
    "id": "id",
}


def _now() -> datetime:
    return datetime.now(UTC)


def group_key(display_name: str, *, fallback: uuid.UUID) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", display_name.lower()).strip("-")[:120]
    return slug or f"scim-{fallback.hex}"


class ProvisioningService:
    """Операции одного authoritative source внутри одной транзакции."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        source: ProvisioningSource,
        provider: IdentityProvider,
        driver: Any,
        reserved_group_keys: Collection[str] = (),
    ) -> None:
        self.session = session
        self.source = source
        self.provider = provider
        self.driver = driver
        # Ключи групп, которые заводит только bootstrap (группы привилегированных
        # scope, ADR-0003): группа источника с таким ключом раздавала бы права
        # администратора.
        self.reserved_group_keys = frozenset(reserved_group_keys)
        self.actor = f"provisioning_source:{source.key}"

    # --- служебное -----------------------------------------------------

    def _event(self, type_: str, aggregate_type: str, aggregate_id: uuid.UUID, **payload) -> None:
        """Событие содержит только идентификаторы.

        `userName`, `displayName` и внешние адреса в journal не публикуются:
        подписчику достаточно стабильных ссылок, чтобы дочитать состояние.
        """

        self.session.add(
            OutboxEvent(
                tenant_id=self.source.tenant_id,
                type=type_,
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                payload={"provisioningSource": self.source.key, **payload},
            )
        )

    def _audit(self, action: str, resource_type: str, resource_id: uuid.UUID, reason: str) -> None:
        self.session.add(
            AuditEvent(
                tenant_id=self.source.tenant_id,
                action=action,
                actor_ref=self.actor,
                resource_type=resource_type,
                resource_id=resource_id,
                outcome="allowed",
                reason=reason,
            )
        )

    def mark_sync(self) -> None:
        """Отметить контакт с authoritative source.

        По этой отметке считается устаревание источника: молчащий SCIM-клиент
        означает, что кадровые изменения перестали доезжать.
        """

        self.source.last_sync_at = _now()
        self.source.stale_alerted_at = None

    @staticmethod
    def _touch(resource: ScimUser | ScimGroup, changed: bool) -> bool:
        if changed:
            resource.version += 1
            resource.updated_at = _now()
        return changed

    @staticmethod
    def ensure_version(resource: ScimUser | ScimGroup, if_match: str) -> None:
        if if_match and if_match.strip() not in {etag(resource.version), "*"}:
            raise ScimFault(412, "resource version does not match If-Match")

    async def _upstream(self, call) -> Any:
        try:
            return await call
        except UpstreamUnavailable as exc:
            # Fail closed: расхождение между IAM и каталогом опаснее отказа.
            raise ScimFault(502, f"upstream identity provider rejected the write: {exc}") from exc

    # --- Users ---------------------------------------------------------

    async def load_user(self, user_id: uuid.UUID) -> ScimUser:
        user = await self.session.scalar(self._user_scope().where(ScimUser.id == user_id))
        if user is None:
            raise ScimFault(404, f"user {user_id} does not exist", scim_type="invalidValue")
        return user

    def _user_scope(self) -> Select[tuple[ScimUser]]:
        """Выборка ограничена tenant и source предъявленного credential."""

        return select(ScimUser).where(
            ScimUser.tenant_id == self.source.tenant_id,
            ScimUser.provisioning_source_id == self.source.id,
        )

    async def query_users(
        self, terms: list[FilterTerm], *, start_index: int, count: int
    ) -> tuple[list[ScimUser], int]:
        statement = self._user_scope()
        for term in terms:
            statement = statement.where(_criterion(ScimUser, term))
        total = await self.session.scalar(select(func.count()).select_from(statement.subquery()))
        rows = await self.session.scalars(
            statement.order_by(ScimUser.created_at, ScimUser.id)
            .offset(start_index - 1)
            .limit(count)
        )
        return list(rows), int(total or 0)

    async def create_user(self, body: ScimUserRequest) -> ScimUser:
        await self._reject_duplicate_user(external_id=body.external_id, user_name=body.user_name)
        upstream = await self._upstream(
            self.driver.create_user(
                external_id=body.external_id, user_name=body.user_name, active=body.active
            )
        )

        principal = Principal(
            kind="human",
            display_name=body.display_name or f"{self.source.key}:{body.external_id}",
            status="active" if body.active else "disabled",
        )
        self.session.add(principal)
        await self.session.flush()
        self.session.add(
            TenantMembership(tenant_id=self.source.tenant_id, principal_id=principal.id)
        )
        identity = ExternalIdentity(
            principal_id=principal.id,
            identity_provider_id=self.provider.id,
            issuer=self.provider.issuer,
            # Пока пользователь не вошёл, реального OIDC `sub` нет. Ставим
            # неколлизионный placeholder; federation найдёт запись по
            # стабильному external ID и заменит subject при первом входе.
            subject=(upstream.user_id or f"urn:iam:scim:{self.source.key}:{body.external_id}")[
                :500
            ],
            external_id=body.external_id,
            source=IDENTITY_SOURCE_PROVISIONED,
            provisioning_source_id=self.source.id,
            status="active" if body.active else "disabled",
        )
        self.session.add(identity)
        user = ScimUser(
            tenant_id=self.source.tenant_id,
            provisioning_source_id=self.source.id,
            external_id=body.external_id,
            user_name=body.user_name,
            display_name=body.display_name,
            principal_id=principal.id,
            active=body.active,
            upstream_user_id=upstream.user_id,
        )
        self.session.add(user)
        try:
            await self.session.flush()
        except IntegrityError as exc:
            await self.session.rollback()
            raise ScimFault(
                409, "user with the same externalId or userName exists", scim_type="uniqueness"
            ) from exc
        user.external_identity_id = identity.id

        self._event(
            "principal.created",
            "principal",
            principal.id,
            principalId=str(principal.id),
            kind=principal.kind,
        )
        self._event(
            "external_identity.linked",
            "external_identity",
            identity.id,
            externalIdentityId=str(identity.id),
            principalId=str(principal.id),
        )
        self._event(
            "scim_user.provisioned",
            "scim_user",
            user.id,
            scimUserId=str(user.id),
            principalId=str(principal.id),
            active=user.active,
        )
        self._audit(
            "scim.users.create",
            "scim_user",
            user.id,
            f"principal:{principal.id} upstream:{upstream.via}",
        )
        return user

    async def _reject_duplicate_user(self, *, external_id: str, user_name: str) -> None:
        existing = await self.session.scalar(
            self._user_scope().where(
                (ScimUser.external_id == external_id) | (ScimUser.user_name == user_name)
            )
        )
        if existing is not None:
            # Повтор create при неопределённом ответе не создаёт второй
            # Principal: тот же externalId остаётся одной identity.
            raise ScimFault(
                409, "user with the same externalId or userName exists", scim_type="uniqueness"
            )

    async def replace_user(self, user: ScimUser, body: ScimUserRequest) -> ScimUser:
        if body.external_id != user.external_id:
            raise ScimFault(
                400, "externalId is immutable for a provisioned user", scim_type="mutability"
            )
        changed = False
        if body.user_name != user.user_name:
            await self._reject_conflicting_user_name(user, body.user_name)
            user.user_name = body.user_name
            changed = True
        if body.display_name != user.display_name:
            user.display_name = body.display_name
            changed = True
        changed = await self._apply_active(user, body.active) or changed
        self._touch(user, changed)
        if changed:
            self._event(
                "scim_user.updated",
                "scim_user",
                user.id,
                scimUserId=str(user.id),
                principalId=str(user.principal_id),
                active=user.active,
            )
            self._audit(
                "scim.users.replace", "scim_user", user.id, f"principal:{user.principal_id}"
            )
        return user

    async def _reject_conflicting_user_name(self, user: ScimUser, user_name: str) -> None:
        clash = await self.session.scalar(
            self._user_scope().where(ScimUser.user_name == user_name, ScimUser.id != user.id)
        )
        if clash is not None:
            raise ScimFault(409, "userName is already taken", scim_type="uniqueness")

    async def patch_user(self, user: ScimUser, operations: list[ScimPatchOperation]) -> ScimUser:
        changed = False
        for operation in operations:
            path = (operation.path or "").strip()
            action = operation.op.lower()
            if action not in {"add", "replace", "remove"}:
                raise ScimFault(400, f"unsupported op {operation.op}", scim_type="invalidSyntax")
            if path == "active":
                value = False if action == "remove" else _as_bool(operation.value)
                changed = await self._apply_active(user, value) or changed
                continue
            if path in {"userName", "displayName"} and action in {"add", "replace"}:
                value = _as_text(operation.value)
                if path == "userName":
                    await self._reject_conflicting_user_name(user, value)
                    changed = changed or user.user_name != value
                    user.user_name = value
                else:
                    changed = changed or user.display_name != value
                    user.display_name = value
                continue
            if path == "" and action == "replace" and isinstance(operation.value, dict):
                changed = await self._patch_user_body(user, operation.value) or changed
                continue
            raise ScimFault(
                400, f"path {path or '(none)'} is not patchable", scim_type="invalidPath"
            )
        self._touch(user, changed)
        if changed:
            self._event(
                "scim_user.updated",
                "scim_user",
                user.id,
                scimUserId=str(user.id),
                principalId=str(user.principal_id),
                active=user.active,
            )
            self._audit("scim.users.patch", "scim_user", user.id, f"principal:{user.principal_id}")
        return user

    async def _patch_user_body(self, user: ScimUser, value: dict[str, Any]) -> bool:
        changed = False
        if "userName" in value:
            user_name = _as_text(value["userName"])
            await self._reject_conflicting_user_name(user, user_name)
            changed = changed or user.user_name != user_name
            user.user_name = user_name
        if "displayName" in value:
            display_name = _as_text(value["displayName"])
            changed = changed or user.display_name != display_name
            user.display_name = display_name
        if "active" in value:
            changed = await self._apply_active(user, _as_bool(value["active"])) or changed
        return changed

    async def _apply_active(self, user: ScimUser, active: bool) -> bool:
        """Синхронизировать состояние lifecycle с upstream и credentials."""

        if bool(user.active) == active:
            return False
        if user.upstream_user_id is not None:
            await self._upstream(
                self.driver.set_user_active(user_id=user.upstream_user_id, active=active)
            )
        user.active = active
        principal = await self.session.get(Principal, user.principal_id)
        identity = (
            await self.session.get(ExternalIdentity, user.external_identity_id)
            if user.external_identity_id is not None
            else None
        )
        if principal is not None:
            if active:
                # Реактивация источником — то же включение, что `:enable`:
                # запись включения отсекает access token, выпущенные до неё,
                # на пути `iam:people`, событие несёт `sessionsNotBefore`.
                # Кадровая система — хозяин lifecycle, поэтому SCIM включает
                # из любого неактивного статуса.
                await mark_principal_enabled(
                    self.session,
                    tenant_id=self.source.tenant_id,
                    principal=principal,
                    source_statuses=frozenset({"disabled", "paused"}),
                )
            else:
                principal.status = "disabled"
        if identity is not None:
            identity.status = "active" if active else "disabled"
        if not active:
            revoked = await revoke_tokens_for_principal(
                self.session,
                tenant_id=self.source.tenant_id,
                principal_id=user.principal_id,
                actor=self.actor,
                reason="scim_deactivated",
            )
            self._event(
                "principal.disabled",
                "principal",
                user.principal_id,
                principalId=str(user.principal_id),
                revokedCredentials=revoked,
            )
        return True

    async def deprovision_user(self, user: ScimUser) -> None:
        """Удаление SCIM-записи: отзыв только того, что породил provisioning.

        Локальные членства и identity других источников остаются нетронутыми —
        удаление в кадровой системе не должно молча стирать ручные решения
        администратора.
        """

        await self._apply_active(user, False)
        memberships = list(
            await self.session.scalars(
                select(GroupMember).where(
                    GroupMember.tenant_id == self.source.tenant_id,
                    GroupMember.principal_id == user.principal_id,
                    GroupMember.source == SOURCE_PROVISIONED,
                    GroupMember.provisioning_source_id == self.source.id,
                )
            )
        )
        for membership in memberships:
            await self.session.delete(membership)
            self._event(
                "group_membership.removed",
                "group",
                membership.group_id,
                groupId=str(membership.group_id),
                principalId=str(user.principal_id),
            )
        principal_id, user_id = user.principal_id, user.id
        await self.session.delete(user)
        self._event(
            "scim_user.deprovisioned",
            "scim_user",
            user_id,
            scimUserId=str(user_id),
            principalId=str(principal_id),
            removedMemberships=len(memberships),
        )
        self._audit(
            "scim.users.delete",
            "scim_user",
            user_id,
            f"principal:{principal_id} memberships:{len(memberships)}",
        )

    # --- Groups --------------------------------------------------------

    def _group_scope(self) -> Select[tuple[ScimGroup]]:
        return select(ScimGroup).where(
            ScimGroup.tenant_id == self.source.tenant_id,
            ScimGroup.provisioning_source_id == self.source.id,
        )

    async def load_group(self, group_id: uuid.UUID) -> ScimGroup:
        group = await self.session.scalar(self._group_scope().where(ScimGroup.id == group_id))
        if group is None:
            raise ScimFault(404, f"group {group_id} does not exist", scim_type="invalidValue")
        return group

    async def query_groups(
        self, terms: list[FilterTerm], *, start_index: int, count: int
    ) -> tuple[list[ScimGroup], int]:
        statement = self._group_scope()
        for term in terms:
            statement = statement.where(_criterion(ScimGroup, term))
        total = await self.session.scalar(select(func.count()).select_from(statement.subquery()))
        rows = await self.session.scalars(
            statement.order_by(ScimGroup.created_at, ScimGroup.id)
            .offset(start_index - 1)
            .limit(count)
        )
        return list(rows), int(total or 0)

    async def create_group(self, body: ScimGroupRequest) -> ScimGroup:
        existing = await self.session.scalar(
            self._group_scope().where(ScimGroup.display_name == body.display_name)
        )
        if existing is not None:
            raise ScimFault(409, "group already exists", scim_type="uniqueness")
        scim_group = ScimGroup(
            tenant_id=self.source.tenant_id,
            provisioning_source_id=self.source.id,
            external_id=body.external_id,
            display_name=body.display_name,
            group_id=uuid.uuid4(),
        )
        key = group_key(body.display_name, fallback=scim_group.group_id)
        if key in self.reserved_group_keys:
            raise ScimFault(409, "group key is reserved", scim_type="uniqueness")
        group = Group(
            id=scim_group.group_id,
            tenant_id=self.source.tenant_id,
            key=key,
            name=body.display_name,
            source=SOURCE_PROVISIONED,
            provisioning_source_id=self.source.id,
        )
        self.session.add(group)
        self.session.add(scim_group)
        try:
            await self.session.flush()
        except IntegrityError as exc:
            await self.session.rollback()
            raise ScimFault(409, "group already exists", scim_type="uniqueness") from exc
        self._event(
            "group.created",
            "group",
            group.id,
            groupId=str(group.id),
            key=group.key,
            source=SOURCE_PROVISIONED,
        )
        self._audit("scim.groups.create", "scim_group", scim_group.id, f"group:{group.id}")
        await self.replace_members(scim_group, [member.value for member in body.members])
        return scim_group

    async def members(self, group: ScimGroup) -> list[GroupMember]:
        return list(
            await self.session.scalars(
                select(GroupMember).where(
                    GroupMember.tenant_id == self.source.tenant_id,
                    GroupMember.group_id == group.group_id,
                    GroupMember.source == SOURCE_PROVISIONED,
                    GroupMember.provisioning_source_id == self.source.id,
                )
            )
        )

    async def member_users(self, group: ScimGroup) -> list[ScimUser]:
        principals = [member.principal_id for member in await self.members(group)]
        if not principals:
            return []
        return list(
            await self.session.scalars(
                self._user_scope().where(ScimUser.principal_id.in_(principals))
            )
        )

    async def user_groups(self, user: ScimUser) -> list[ScimGroup]:
        group_ids = [
            member.group_id
            for member in await self.session.scalars(
                select(GroupMember).where(
                    GroupMember.tenant_id == self.source.tenant_id,
                    GroupMember.principal_id == user.principal_id,
                    GroupMember.source == SOURCE_PROVISIONED,
                    GroupMember.provisioning_source_id == self.source.id,
                )
            )
        ]
        if not group_ids:
            return []
        return list(
            await self.session.scalars(self._group_scope().where(ScimGroup.group_id.in_(group_ids)))
        )

    async def replace_members(self, group: ScimGroup, member_ids: list[str]) -> bool:
        desired = {await self._member_principal(value) for value in member_ids}
        current = {member.principal_id: member for member in await self.members(group)}
        changed = False
        for principal_id, member in current.items():
            if principal_id in desired:
                continue
            await self.session.delete(member)
            self._membership_event("group_membership.removed", group, principal_id)
            changed = True
        for principal_id in desired - set(current):
            self._add_member(group, principal_id)
            changed = True
        return changed

    async def patch_group(
        self, group: ScimGroup, operations: list[ScimPatchOperation]
    ) -> ScimGroup:
        changed = False
        for operation in operations:
            action = operation.op.lower()
            path = (operation.path or "").strip()
            if action in {"add", "replace"} and path == "displayName":
                value = _as_text(operation.value)
                changed = changed or group.display_name != value
                group.display_name = value
                continue
            if path.startswith("members"):
                changed = await self._patch_members(group, action, path, operation.value) or changed
                continue
            if action == "replace" and path == "" and isinstance(operation.value, dict):
                if "members" in operation.value:
                    changed = (
                        await self.replace_members(
                            group, _member_values(operation.value["members"])
                        )
                        or changed
                    )
                if "displayName" in operation.value:
                    value = _as_text(operation.value["displayName"])
                    changed = changed or group.display_name != value
                    group.display_name = value
                continue
            raise ScimFault(
                400, f"path {path or '(none)'} is not patchable", scim_type="invalidPath"
            )
        self._touch(group, changed)
        if changed:
            self._audit("scim.groups.patch", "scim_group", group.id, f"group:{group.group_id}")
        return group

    async def _patch_members(self, group: ScimGroup, action: str, path: str, value: Any) -> bool:
        if action == "replace" and path == "members":
            return await self.replace_members(group, _member_values(value))
        if action == "add":
            changed = False
            current = {member.principal_id for member in await self.members(group)}
            for raw in _member_values(value):
                principal_id = await self._member_principal(raw)
                if principal_id in current:
                    # Повтор add идемпотентен: второй раз членство не создаётся.
                    continue
                self._add_member(group, principal_id)
                current.add(principal_id)
                changed = True
            return changed
        if action == "remove":
            targets = _member_filter(path) or [
                str(value_id) for value_id in _member_values(value or [])
            ]
            current = {member.principal_id: member for member in await self.members(group)}
            changed = False
            for raw in targets:
                principal_id = await self._member_principal(raw)
                member = current.get(principal_id)
                if member is None:
                    continue
                await self.session.delete(member)
                self._membership_event("group_membership.removed", group, principal_id)
                changed = True
            return changed
        raise ScimFault(400, f"unsupported members op {action}", scim_type="invalidSyntax")

    def _add_member(self, group: ScimGroup, principal_id: uuid.UUID) -> None:
        self.session.add(
            GroupMember(
                tenant_id=self.source.tenant_id,
                group_id=group.group_id,
                principal_id=principal_id,
                source=SOURCE_PROVISIONED,
                provisioning_source_id=self.source.id,
            )
        )
        self._membership_event("group_membership.added", group, principal_id)

    def _membership_event(self, type_: str, group: ScimGroup, principal_id: uuid.UUID) -> None:
        self._event(
            type_,
            "group",
            group.group_id,
            groupId=str(group.group_id),
            principalId=str(principal_id),
        )

    async def _member_principal(self, value: str) -> uuid.UUID:
        try:
            member_id = uuid.UUID(str(value))
        except ValueError as exc:
            raise ScimFault(
                400, f"member {value} is not a SCIM id", scim_type="invalidValue"
            ) from exc
        user = await self.session.scalar(self._user_scope().where(ScimUser.id == member_id))
        if user is None:
            raise ScimFault(400, f"member {value} does not exist", scim_type="invalidValue")
        return user.principal_id

    async def deprovision_group(self, group: ScimGroup) -> None:
        """Группа целиком принадлежит source, поэтому удаляется вместе с ним.

        Локальный API не умеет добавлять участников в provisioned-группу, так
        что ручных членств здесь быть не может.
        """

        for member in await self.members(group):
            await self.session.delete(member)
            self._membership_event("group_membership.removed", group, member.principal_id)
        group_id, scim_id = group.group_id, group.id
        await self.session.delete(group)
        await self.session.flush()
        iam_group = await self.session.get(Group, group_id)
        if iam_group is not None:
            await self.session.delete(iam_group)
        self._event("group.deleted", "group", group_id, groupId=str(group_id))
        self._audit("scim.groups.delete", "scim_group", scim_id, f"group:{group_id}")


def _criterion(model: Any, term: FilterTerm) -> Any:
    column = getattr(model, term.attribute)
    if term.attribute != "id":
        return column == term.value
    try:
        return column == uuid.UUID(str(term.value))
    except ValueError as exc:
        raise ScimFault(400, "id filter expects a SCIM id", scim_type="invalidFilter") from exc


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "false"}:
        return value.lower() == "true"
    raise ScimFault(400, "expected a boolean value", scim_type="invalidValue")


def _as_text(value: Any) -> str:
    if isinstance(value, str) and value:
        return value
    raise ScimFault(400, "expected a non-empty string value", scim_type="invalidValue")


def _member_values(value: Any) -> list[str]:
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        raise ScimFault(400, "members must be an array", scim_type="invalidValue")
    values: list[str] = []
    for item in value:
        if isinstance(item, dict) and "value" in item:
            values.append(str(item["value"]))
        elif isinstance(item, str):
            values.append(item)
        else:
            raise ScimFault(400, "member entry has no value", scim_type="invalidValue")
    return values


_MEMBER_FILTER = re.compile(r'^members\[\s*value\s+eq\s+"(?P<value>[^"]+)"\s*\]$', re.IGNORECASE)


def _member_filter(path: str) -> list[str]:
    """`members[value eq "id"]` — типовая форма удаления одного участника."""

    match = _MEMBER_FILTER.match(path.strip())
    return [match.group("value")] if match else []
