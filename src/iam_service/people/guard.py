"""Кто вызывает маршрут управления людьми: bootstrap или человек со `iam:people`.

Человек предъявляет access token IAM (audience `IAM_PEOPLE_AUDIENCE`) с
`principal_type = human` и scope `IAM_PEOPLE_SCOPE`. Scope выдаётся только
federation-входом: `credential_id` такого token — активная federated external
identity самого человека. Token после обмена PAT, client credentials или
assertion канала сюда не проходит, даже если scope в нём оказался.

Кто из людей администратор, решает политика IAM, а не заголовок запроса:
scope должен быть в allowed scopes audience, а сам человек — членом группы
`IAM_PEOPLE_ADMIN_GROUP` tenant'а. Отключение человека, его identity,
membership или провайдера и выход из группы закрывают путь сразу — по записи,
а не по истечению token.
"""

from __future__ import annotations

import hmac
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC
from typing import Any

from fastapi import Depends, Header, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from iam_service.config import Settings
from iam_service.models import (
    AuditEvent,
    ExternalIdentity,
    IdentityProvider,
    Principal,
    PrincipalEnablement,
    Tenant,
    TenantMembership,
)
from iam_service.privileged import is_group_member
from iam_service.tokens import TokenIssuer, verify_access_token

BOOTSTRAP_ACTOR = "bootstrap"


@dataclass(frozen=True)
class Caller:
    """Вызывающий маршрута управления людьми.

    `actor_ref` пишется в audit: `bootstrap` или id Principal человека.
    """

    actor_ref: str
    principal_id: uuid.UUID | None = None
    external_identity_id: uuid.UUID | None = None

    @property
    def bootstrap(self) -> bool:
        return self.principal_id is None


async def refuse(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    action: str,
    actor_ref: str,
    resource_id: uuid.UUID,
    status_code: int,
    detail: str,
    reason: str = "",
) -> HTTPException:
    """Записать отказ в audit (с точной причиной) и вернуть исключение.

    `resource_type` отказов всегда `principal`: `resource_id` — Principal,
    к которому относилось действие, а где цели нет (создание, вход) — сам
    вызывающий.
    """

    await session.rollback()
    session.add(
        AuditEvent(
            tenant_id=tenant_id,
            action=action,
            actor_ref=actor_ref,
            resource_type="principal",
            resource_id=resource_id,
            outcome="denied",
            reason=(reason or detail)[:1000],
        )
    )
    await session.commit()
    return HTTPException(status_code=status_code, detail=detail)


async def is_people_admin(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    principal_id: uuid.UUID,
    group_key: str,
) -> bool:
    """Член ли человек активной группы администраторов людей tenant'а.

    Правило общее для привилегированных scope (`iam_service.privileged`):
    группа — только заведённая bootstrap, членство — любого источника.
    """

    return await is_group_member(
        session, tenant_id=tenant_id, principal_id=principal_id, group_key=group_key
    )


async def require_human_target(
    session: AsyncSession,
    caller: Caller,
    *,
    tenant_id: uuid.UUID,
    principal: Principal,
    action: str,
) -> None:
    """Scope `iam:people` управляет только людьми.

    Агентами управляет их владелец (`iam:agents`), service account и workload
    — bootstrap. Bootstrap ограничений по виду не имеет.
    """

    if caller.bootstrap or principal.kind == "human":
        return
    principal_id, kind = principal.id, principal.kind
    raise await refuse(
        session,
        tenant_id=tenant_id,
        action=action,
        actor_ref=caller.actor_ref,
        resource_id=principal_id,
        status_code=422,
        detail="human_principal_required",
        reason=f"kind:{kind}",
    )


async def issued_before_enable(
    session: AsyncSession, *, principal_id: uuid.UUID, issued_at: Any
) -> bool:
    """Выпущен ли access token до последнего включения Principal после отключения.

    `iat` token — целые секунды, момент включения — с долями: сравнение идёт
    по целой секунде включения, чтобы token, выпущенный в ту же секунду сразу
    после него, не отвергался. No-op включение (`previous_status = active`)
    сессий не закрывало и ничего не отсекает.
    """

    enabled_at = await session.scalar(
        select(func.max(PrincipalEnablement.enabled_at)).where(
            PrincipalEnablement.principal_id == principal_id,
            PrincipalEnablement.previous_status != "active",
        )
    )
    if enabled_at is None:
        return False
    if enabled_at.tzinfo is None:
        enabled_at = enabled_at.replace(tzinfo=UTC)
    try:
        issued = int(issued_at)
    except (TypeError, ValueError):
        return True
    return issued < int(enabled_at.timestamp())


def _uuid_claim(claims: dict[str, Any], name: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(claims.get(name)))
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid_token") from exc


def create_people_guard(
    *,
    settings: Settings,
    get_session: Callable[..., Any],
) -> Callable[..., Any]:
    """Зависимость FastAPI: bootstrap-токен или Bearer человека со `iam:people`."""

    def public_key() -> Any:
        return TokenIssuer(
            issuer=settings.issuer,
            private_key=settings.resolved_signing_private_key(),
            key_id=settings.signing_key_id,
            ttl_seconds=settings.token_ttl_seconds,
        ).private_key.public_key()

    async def people_caller(
        tenant_id: uuid.UUID,
        x_iam_bootstrap_token: str = Header(default=""),
        authorization: str = Header(default=""),
        session: AsyncSession = Depends(get_session),
    ) -> Caller:
        # Предъявленный bootstrap-токен проверяется как прежде и не уступает
        # место Bearer: неверный bootstrap — 401, а не попытка другого пути.
        if x_iam_bootstrap_token or not authorization:
            expected = settings.bootstrap_token
            if not expected or not hmac.compare_digest(x_iam_bootstrap_token, expected):
                raise HTTPException(status_code=401, detail="unauthorized")
            return Caller(actor_ref=BOOTSTRAP_ACTOR)

        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise HTTPException(status_code=401, detail="invalid_token")
        try:
            claims = verify_access_token(
                token.strip(),
                public_key=public_key(),
                issuer=settings.issuer,
                audience=settings.people_audience,
            )
        except Exception as exc:
            raise HTTPException(status_code=401, detail="invalid_token") from exc
        # Tenant из пути авторитетным не бывает: только из подписанного token.
        if claims.get("tenant_id") != str(tenant_id):
            raise HTTPException(status_code=403, detail="tenant_mismatch")
        subject = _uuid_claim(claims, "sub")
        credential_id = _uuid_claim(claims, "credential_id")
        action = "people.authenticate"

        async def deny(detail: str, reason: str = "", status_code: int = 403) -> HTTPException:
            return await refuse(
                session,
                tenant_id=tenant_id,
                action=action,
                actor_ref=str(subject),
                resource_id=subject,
                status_code=status_code,
                detail=detail,
                reason=reason,
            )

        if claims.get("principal_type") != "human":
            raise await deny("human_required", f"principal_type:{claims.get('principal_type')}")
        if settings.people_scope not in set(claims.get("scope") or []):
            raise await deny("scope_not_granted")
        identity = await session.scalar(
            select(ExternalIdentity).where(
                ExternalIdentity.id == credential_id,
                ExternalIdentity.principal_id == subject,
            )
        )
        # Token человека, выпущенный не federation-входом (обмен PAT), держит
        # другой credential: scope `iam:people` ему не положен.
        if identity is None or identity.identity_provider_id is None:
            raise await deny("federation_required", f"credential:{credential_id}")
        provider = await session.get(IdentityProvider, identity.identity_provider_id)
        tenant = await session.get(Tenant, tenant_id)
        membership = await session.get(
            TenantMembership, {"tenant_id": tenant_id, "principal_id": subject}
        )
        principal = await session.get(Principal, subject)
        if tenant is None:
            # Tenant нет: записи audit негде жить.
            raise HTTPException(status_code=401, detail="invalid_token")
        closed = [
            name
            for name, ok in (
                ("tenant", tenant.status == "active"),
                ("identity", identity.status == "active"),
                (
                    "provider",
                    provider is not None
                    and provider.tenant_id == tenant_id
                    and provider.status == "active",
                ),
                ("membership", membership is not None and membership.status == "active"),
                ("principal", principal is not None and principal.status == "active"),
            )
            if not ok
        ]
        if closed:
            raise await deny("invalid_token", f"closed:{','.join(closed)}", status_code=401)
        # Отключение закрыло все сессии человека; `:enable` их не оживляет —
        # token, выпущенный до включения, не принимается (ADR-0002, п. 12).
        if await issued_before_enable(session, principal_id=subject, issued_at=claims.get("iat")):
            raise await deny("invalid_token", "closed:session", status_code=401)
        # Администратор людей — член группы tenant'а, а не любой вошедший:
        # выход из группы закрывает путь, не дожидаясь истечения token.
        admin_group = settings.people_admin_group
        if not await is_people_admin(
            session, tenant_id=tenant_id, principal_id=subject, group_key=admin_group
        ):
            raise await deny("people_admin_required", f"group:{admin_group}")
        return Caller(
            actor_ref=str(subject), principal_id=subject, external_identity_id=identity.id
        )

    return people_caller
