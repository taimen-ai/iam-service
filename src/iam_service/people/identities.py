"""Кто вызывает маршрут identity: bootstrap, человек со `iam:people` или агент
со `iam:identities.link` (ADR-0004, п. 5).

Держатель `iam:identities.link` — только агент: token его обмена PAT
(audience `IAM_PEOPLE_AUDIENCE`, `principal_type = agent`). На каждом запросе
проверяется, что `credential_id` token — PAT этого агента, не отозванный и не
истёкший, а агент, его membership и tenant активны: отзыв PAT или отключение
агента закрывают путь сразу, не дожидаясь истечения token.

Человек на тех же маршрутах проходит guard `iam:people` — scope
`iam:identities.link` ему ничего не даёт. Service account и workload с этим
scope — `403 agent_required`.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from iam_service.config import Settings
from iam_service.models import Principal, Tenant, TenantMembership
from iam_service.pat.models import PlatformAccessToken
from iam_service.people.guard import Caller, _uuid_claim, issued_before_enable, refuse
from iam_service.tokens import TokenIssuer, verify_access_token


def _as_aware(value: datetime | None) -> datetime | None:
    """SQLite отдаёт naive datetime; сравнения ведём в UTC."""

    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def create_identities_guard(
    *,
    settings: Settings,
    get_session: Callable[..., Any],
    people_caller: Callable[..., Any],
) -> Callable[..., Any]:
    """Зависимость FastAPI: bootstrap, Bearer `iam:people` или агент `iam:identities.link`.

    Bootstrap и Bearer человека целиком отдаются `people_caller`, поэтому
    правила `iam:people` (federation, группа администраторов) на этих
    маршрутах те же, что на остальных маршрутах людей.
    """

    def public_key() -> Any:
        return TokenIssuer(
            issuer=settings.issuer,
            private_key=settings.resolved_signing_private_key(),
            key_id=settings.signing_key_id,
            ttl_seconds=settings.token_ttl_seconds,
        ).private_key.public_key()

    async def identities_caller(
        tenant_id: uuid.UUID,
        x_iam_bootstrap_token: str = Header(default=""),
        authorization: str = Header(default=""),
        session: AsyncSession = Depends(get_session),
    ) -> Caller:
        async def people() -> Caller:
            return await people_caller(
                tenant_id=tenant_id,
                x_iam_bootstrap_token=x_iam_bootstrap_token,
                authorization=authorization,
                session=session,
            )

        if x_iam_bootstrap_token or not authorization:
            return await people()
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
        principal_type = claims.get("principal_type")
        has_scope = settings.identities_link_scope in set(claims.get("scope") or [])
        if principal_type == "human" or (principal_type != "agent" and not has_scope):
            # Человек — всегда guard `iam:people`; прочие без scope подключений
            # получают от него прежний `human_required`.
            return await people()

        subject = _uuid_claim(claims, "sub")
        credential_id = _uuid_claim(claims, "credential_id")

        async def deny(detail: str, reason: str = "", status_code: int = 403) -> HTTPException:
            return await refuse(
                session,
                tenant_id=tenant_id,
                action="identities.authenticate",
                actor_ref=str(subject),
                resource_id=subject,
                status_code=status_code,
                detail=detail,
                reason=reason,
            )

        if principal_type != "agent":
            raise await deny("agent_required", f"principal_type:{principal_type}")
        if not has_scope:
            raise await deny("scope_not_granted")
        tenant = await session.get(Tenant, tenant_id)
        if tenant is None:
            # Tenant нет: записи audit негде жить.
            raise HTTPException(status_code=401, detail="invalid_token")
        credential = await session.get(PlatformAccessToken, credential_id)
        membership = await session.get(
            TenantMembership, {"tenant_id": tenant_id, "principal_id": subject}
        )
        principal = await session.get(Principal, subject)
        expires_at = _as_aware(credential.expires_at) if credential is not None else None
        closed = [
            name
            for name, ok in (
                ("tenant", tenant.status == "active"),
                # Token агента выпускает только обмен его PAT: иной credential
                # (или PAT другого Principal) этот scope не несёт.
                (
                    "credential",
                    credential is not None
                    and credential.principal_id == subject
                    and credential.tenant_id == tenant_id
                    and credential.revoked_at is None
                    and expires_at is not None
                    and expires_at > datetime.now(UTC),
                ),
                ("membership", membership is not None and membership.status == "active"),
                (
                    "principal",
                    principal is not None
                    and principal.kind == "agent"
                    and principal.status == "active",
                ),
            )
            if not ok
        ]
        if closed:
            raise await deny("invalid_token", f"closed:{','.join(closed)}", status_code=401)
        if await issued_before_enable(session, principal_id=subject, issued_at=claims.get("iat")):
            raise await deny("invalid_token", "closed:session", status_code=401)
        return Caller(
            actor_ref=str(subject), principal_id=subject, agent=True, credential_id=credential_id
        )

    return identities_caller
