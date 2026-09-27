"""Агенты владельца: заведение и Platform Access Token без bootstrap-токена.

Предъявитель — confidential service account (контроллер агентов) с token
audience IAM и scope `iam:agents`. Он может:

1. завести Principal вида `agent`, владельцем которого становится сам, —
   `POST …/agents`;
2. выпустить своему агенту PAT — `POST …/agents/{id}/platform-access-tokens`
   (обязательные `Idempotency-Key` и `expiresInSeconds`);
3. отозвать PAT своего агента — `POST …/agents/{id}/platform-access-tokens/
   {credentialId}:revoke`.

Чужой агент — 403, principal другого вида — 422; оба отказа пишутся в audit.
Authority агента не шире authority владельца: audiences и потолок scope PAT
агента — подмножество audiences и потолка service account, а сам scope
`iam:agents` не делегируется.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from iam_service.agents.schemas import AgentCreate, AgentPlatformAccessTokenCreate, AgentView
from iam_service.config import Settings
from iam_service.models import (
    Audience,
    AuditEvent,
    OutboxEvent,
    Principal,
    ServiceAccount,
    Tenant,
    TenantMembership,
)
from iam_service.pat import (
    PlatformAccessToken,
    credential_payload,
    generate_platform_access_token,
    revoke_credential,
)
from iam_service.pat.material import KIND_PLATFORM_ACCESS_TOKEN
from iam_service.pat.schemas import PlatformAccessTokenIssued, PlatformAccessTokenView
from iam_service.tokens import TokenIssuer, verify_access_token


def _now() -> datetime:
    return datetime.now(UTC)


def _uuid_claim(claims: dict[str, Any], name: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(claims.get(name)))
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid_token") from exc


def create_agent_router(
    *,
    settings: Settings,
    get_session: Callable[..., Any],
) -> APIRouter:
    # Bootstrap-токен здесь не принимается сознательно: весь смысл пути в том,
    # что контроллер агентов работает без него и не выходит за своих агентов.
    router = APIRouter(tags=["agents"])

    def public_key() -> Any:
        return TokenIssuer(
            issuer=settings.issuer,
            private_key=settings.resolved_signing_private_key(),
            key_id=settings.signing_key_id,
            ttl_seconds=settings.token_ttl_seconds,
        ).private_key.public_key()

    async def refuse(
        session: AsyncSession,
        *,
        tenant_id: uuid.UUID,
        action: str,
        actor_ref: str,
        resource_type: str,
        resource_id: uuid.UUID,
        status_code: int,
        detail: str,
        reason: str = "",
    ) -> HTTPException:
        """Записать отказ в audit (с точной причиной) и вернуть исключение."""

        await session.rollback()
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action=action,
                actor_ref=actor_ref,
                resource_type=resource_type,
                resource_id=resource_id,
                outcome="denied",
                reason=(reason or detail)[:1000],
            )
        )
        await session.commit()
        return HTTPException(status_code=status_code, detail=detail)

    async def agent_owner(
        tenant_id: uuid.UUID,
        authorization: str = Header(default=""),
        session: AsyncSession = Depends(get_session),
    ) -> ServiceAccount:
        """Service account со scope `iam:agents` — и только он.

        Отзыв service account, отключение его Principal или membership
        действуют сразу, не дожидаясь истечения его token: выпуск credential
        агента — это выпуск authority.
        """

        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise HTTPException(status_code=401, detail="invalid_token")
        try:
            claims = verify_access_token(
                token.strip(),
                public_key=public_key(),
                issuer=settings.issuer,
                audience=settings.agents_audience,
            )
        except Exception as exc:
            raise HTTPException(status_code=401, detail="invalid_token") from exc
        # Tenant из пути авторитетным не бывает: только из подписанного token.
        if claims.get("tenant_id") != str(tenant_id):
            raise HTTPException(status_code=403, detail="tenant_mismatch")
        subject = _uuid_claim(claims, "sub")
        action = "agents.authenticate"
        if claims.get("principal_type") != "service_account":
            raise await refuse(
                session,
                tenant_id=tenant_id,
                action=action,
                actor_ref=str(subject),
                resource_type="principal",
                resource_id=subject,
                status_code=403,
                detail="service_account_required",
                reason=f"principal_type:{claims.get('principal_type')}",
            )
        if settings.agents_scope not in set(claims.get("scope") or []):
            raise await refuse(
                session,
                tenant_id=tenant_id,
                action=action,
                actor_ref=str(subject),
                resource_type="principal",
                resource_id=subject,
                status_code=403,
                detail="scope_not_granted",
            )
        account = await session.scalar(
            select(ServiceAccount).where(
                ServiceAccount.id == _uuid_claim(claims, "credential_id"),
                ServiceAccount.tenant_id == tenant_id,
                ServiceAccount.principal_id == subject,
                ServiceAccount.revoked_at.is_(None),
            )
        )
        tenant = await session.get(Tenant, tenant_id)
        membership = await session.get(
            TenantMembership, {"tenant_id": tenant_id, "principal_id": subject}
        )
        principal = await session.get(Principal, subject)
        if (
            account is None
            or tenant is None
            or tenant.status != "active"
            or membership is None
            or membership.status != "active"
            or principal is None
            or principal.status != "active"
        ):
            raise HTTPException(status_code=401, detail="invalid_token")
        return account

    async def owned_agent(
        session: AsyncSession,
        *,
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        account: ServiceAccount,
        action: str,
    ) -> Principal:
        """Principal-агент tenant, которым владеет именно этот service account."""

        principal = await session.scalar(
            select(Principal)
            .join(TenantMembership, TenantMembership.principal_id == Principal.id)
            .where(
                TenantMembership.tenant_id == tenant_id,
                TenantMembership.principal_id == agent_id,
            )
        )
        if principal is None:
            raise HTTPException(status_code=404, detail="agent_not_found")
        owner = account.principal_id
        if principal.kind != "agent":
            raise await refuse(
                session,
                tenant_id=tenant_id,
                action=action,
                actor_ref=str(owner),
                resource_type="principal",
                resource_id=agent_id,
                status_code=422,
                detail="agent_principal_required",
                reason=f"kind:{principal.kind}",
            )
        if principal.owner_principal_id != owner:
            raise await refuse(
                session,
                tenant_id=tenant_id,
                action=action,
                actor_ref=str(owner),
                resource_type="principal",
                resource_id=agent_id,
                status_code=403,
                detail="agent_not_owned",
                reason=f"owner:{principal.owner_principal_id or 'none'}",
            )
        return principal

    def issued(credential: PlatformAccessToken, token: str | None) -> PlatformAccessTokenIssued:
        return PlatformAccessTokenIssued(
            credential=PlatformAccessTokenView.model_validate(credential), token=token
        )

    async def replayed(
        session: AsyncSession, tenant_id: uuid.UUID, idempotency_key: str
    ) -> PlatformAccessToken | None:
        return await session.scalar(
            select(PlatformAccessToken).where(
                PlatformAccessToken.tenant_id == tenant_id,
                PlatformAccessToken.idempotency_key == idempotency_key,
            )
        )

    @router.post(
        "/api/v1/tenants/{tenant_id}/agents",
        response_model=AgentView,
        status_code=201,
    )
    async def create_agent(
        tenant_id: uuid.UUID,
        body: AgentCreate,
        account: ServiceAccount = Depends(agent_owner),
        session: AsyncSession = Depends(get_session),
    ) -> AgentView:
        """Завести Principal вида `agent`, владельцем которого станет вызывающий."""

        owner = account.principal_id
        principal = Principal(
            kind="agent", display_name=body.display_name, owner_principal_id=owner
        )
        session.add(principal)
        await session.flush()
        session.add(TenantMembership(tenant_id=tenant_id, principal_id=principal.id))
        session.add(
            OutboxEvent(
                tenant_id=tenant_id,
                type="principal.created",
                aggregate_type="principal",
                aggregate_id=principal.id,
                payload={
                    "principalId": str(principal.id),
                    "kind": principal.kind,
                    "ownerPrincipalId": str(owner),
                },
            )
        )
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action="agents.create",
                actor_ref=str(owner),
                resource_type="principal",
                resource_id=principal.id,
                outcome="allowed",
                reason=f"service_account:{account.id}",
            )
        )
        view = AgentView.model_validate(principal)
        await session.commit()
        return view

    @router.post(
        "/api/v1/tenants/{tenant_id}/agents/{agent_id}/platform-access-tokens",
        response_model=PlatformAccessTokenIssued,
        status_code=201,
    )
    async def issue_agent_platform_access_token(
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        body: AgentPlatformAccessTokenCreate,
        response: Response,
        idempotency_key: str = Header(default="", alias="Idempotency-Key"),
        account: ServiceAccount = Depends(agent_owner),
        session: AsyncSession = Depends(get_session),
    ) -> PlatformAccessTokenIssued:
        if not idempotency_key:
            raise HTTPException(status_code=400, detail="idempotency_key_required")
        action = "agents.platform_access_tokens.issue"
        owner = account.principal_id
        agent = await owned_agent(
            session, tenant_id=tenant_id, agent_id=agent_id, account=account, action=action
        )
        # Replay проверяется после владения: чужой ключ не отвечает даже
        # метаданными чужого credential.
        existing = await replayed(session, tenant_id, idempotency_key)
        if existing is not None:
            if existing.principal_id != agent.id:
                raise HTTPException(status_code=409, detail="idempotency_key_reused")
            response.headers["Idempotency-Replayed"] = "true"
            return issued(existing, None)

        membership = await session.get(
            TenantMembership, {"tenant_id": tenant_id, "principal_id": agent.id}
        )
        if agent.status != "active" or membership is None or membership.status != "active":
            raise HTTPException(status_code=409, detail="principal_not_active")
        if body.expires_in_seconds > settings.agent_pat_max_ttl_seconds:
            raise HTTPException(status_code=422, detail="expiry_too_long")

        audiences = sorted(set(body.audiences))
        ceiling = sorted(set(body.scope_ceiling))

        async def deny(detail: str) -> HTTPException:
            return await refuse(
                session,
                tenant_id=tenant_id,
                action=action,
                actor_ref=str(owner),
                resource_type="principal",
                resource_id=agent.id,
                status_code=422,
                detail=detail,
                reason=f"{detail} audiences:{','.join(audiences)} scopes:{','.join(ceiling)}",
            )

        rows = await session.scalars(
            select(Audience).where(
                Audience.tenant_id == tenant_id,
                Audience.status == "active",
                Audience.key.in_(audiences),
            )
        )
        resolved = {row.key: row for row in rows}
        if set(resolved) != set(audiences):
            raise await deny("unknown_audience")
        permitted = {scope for row in resolved.values() for scope in row.allowed_scopes}
        if not set(ceiling).issubset(permitted):
            raise await deny("invalid_scope_ceiling")
        # Агент не получает больше, чем держит владелец, и не получает права
        # заводить агентов сам.
        if not set(audiences).issubset(account.audiences):
            raise await deny("audience_not_delegable")
        if settings.agents_scope in ceiling or not set(ceiling).issubset(account.scope_ceiling):
            raise await deny("scope_not_delegable")

        material = generate_platform_access_token()
        credential = PlatformAccessToken(
            tenant_id=tenant_id,
            principal_id=agent.id,
            name=body.name,
            kind=KIND_PLATFORM_ACCESS_TOKEN,
            public_prefix=material.public_prefix,
            secret_hash=material.secret_hash,
            audiences=audiences,
            scope_ceiling=ceiling,
            # Человеческого входа у агента нет и не имитируется: снимок честно
            # называет владельца, который выпустил credential.
            authentication_context={
                "source": "agent_owner",
                "ownerPrincipalId": str(owner),
                "serviceAccountId": str(account.id),
                "recordedAt": _now().isoformat(),
            },
            idempotency_key=idempotency_key,
            expires_at=_now() + timedelta(seconds=body.expires_in_seconds),
        )
        session.add(credential)
        try:
            await session.flush()
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="platform_access_token.issued",
                    aggregate_type="platform_access_token",
                    aggregate_id=credential.id,
                    payload={**credential_payload(credential), "ownerPrincipalId": str(owner)},
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="platform_access_tokens.issue",
                    actor_ref=str(owner),
                    resource_type="platform_access_token",
                    resource_id=credential.id,
                    outcome="allowed",
                    reason=f"pat:{credential.public_prefix} principal:{agent.id} owner:{owner}",
                )
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            concurrent = await replayed(session, tenant_id, idempotency_key)
            if concurrent is None or concurrent.principal_id != agent_id:
                raise HTTPException(status_code=409, detail="credential_conflict") from exc
            response.headers["Idempotency-Replayed"] = "true"
            return issued(concurrent, None)
        return issued(credential, material.full_token)

    @router.post(
        "/api/v1/tenants/{tenant_id}/agents/{agent_id}/platform-access-tokens/{credential_id}:revoke",
        status_code=204,
    )
    async def revoke_agent_platform_access_token(
        tenant_id: uuid.UUID,
        agent_id: uuid.UUID,
        credential_id: uuid.UUID,
        reason: str = Query(default="revoked", max_length=200),
        account: ServiceAccount = Depends(agent_owner),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        """Отозвать PAT своего агента; следующий обмен получит `invalid_token`.

        Отзыв доступен и для приостановленного или отключённого агента:
        закрыть доступ владелец должен мочь всегда.
        """

        agent = await owned_agent(
            session,
            tenant_id=tenant_id,
            agent_id=agent_id,
            account=account,
            action="agents.platform_access_tokens.revoke",
        )
        credential = await session.scalar(
            select(PlatformAccessToken).where(
                PlatformAccessToken.tenant_id == tenant_id,
                PlatformAccessToken.principal_id == agent.id,
                PlatformAccessToken.id == credential_id,
            )
        )
        if credential is None:
            raise HTTPException(status_code=404, detail="credential_not_found")
        if credential.revoked_at is None:
            revoke_credential(session, credential, actor=str(account.principal_id), reason=reason)
            await session.commit()
        return Response(status_code=204)

    return router
