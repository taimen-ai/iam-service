"""Endpoints выпуска, ротации, отзыва и обмена Platform Access Token.

Роутер собирается фабрикой и получает зависимости приложения снаружи, поэтому
`iam_service.app` подключает его одной строкой и не обрастает логикой PAT.
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

from iam_service.config import Settings
from iam_service.models import (
    Audience,
    AuditEvent,
    OutboxEvent,
    Principal,
    Tenant,
    TenantMembership,
)
from iam_service.pat.material import (
    KIND_LEGACY_CONTROL_PLANE_API_KEY,
    KIND_PLATFORM_ACCESS_TOKEN,
    generate_platform_access_token,
    is_valid_hash,
    is_valid_prefix,
    matches_stored_hash,
    parse_presented_credential,
)
from iam_service.pat.models import AuthenticationContext, PlatformAccessToken
from iam_service.pat.schemas import (
    AuthenticationContextRecord,
    AuthenticationContextView,
    LegacyCredentialImport,
    PlatformAccessTokenCreate,
    PlatformAccessTokenIssued,
    PlatformAccessTokenRotate,
    PlatformAccessTokenView,
    PlatformTokenExchangeRequest,
    PlatformTokenExchangeResponse,
    PrincipalDisabled,
)
from iam_service.tokens import TokenIssuer

# Единый ответ на любой дефект предъявленного токена: отозван, истёк, не найден
# или принадлежит отключённому Principal. Точная причина уходит только в audit,
# чтобы endpoint не работал оракулом для перебора.
_INVALID_TOKEN = "invalid_token"
_ABSENT_HASH = "0" * 64


def _now() -> datetime:
    return datetime.now(UTC)


def _as_aware(value: datetime | None) -> datetime | None:
    """SQLite отдаёт naive datetime; сравнения ведём в UTC."""

    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _credential_payload(credential: PlatformAccessToken) -> dict[str, Any]:
    """Payload события: идентификаторы и prefix, никогда не секрет."""

    return {
        "credentialId": str(credential.id),
        "principalId": str(credential.principal_id),
        "publicPrefix": credential.public_prefix,
        "kind": credential.kind,
        "audiences": list(credential.audiences),
    }


def record_authentication_context(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    principal_id: uuid.UUID,
    issuer: str,
    acr: str | None = None,
    amr: list[str] | None = None,
    auth_time: datetime | None = None,
    external_identity_id: uuid.UUID | None = None,
    source: str = "federation",
) -> AuthenticationContext:
    """Зафиксировать подтверждённый вход человека.

    Экспортируется для federation-входа (IAM-2): после успешной проверки
    upstream token достаточно вызвать эту функцию, чтобы Principal получил
    право выпустить Platform Access Token. Коммит остаётся за вызывающим.
    Будущий `auth_time` подрезается до серверного времени, чтобы снимок не
    выглядел новее, чем момент записи.
    """

    recorded_at = _now()
    claimed = _as_aware(auth_time) or recorded_at
    context = AuthenticationContext(
        tenant_id=tenant_id,
        principal_id=principal_id,
        external_identity_id=external_identity_id,
        issuer=issuer,
        acr=acr,
        amr=sorted(set(amr or [])),
        auth_time=min(claimed, recorded_at),
        recorded_at=recorded_at,
        source=source,
    )
    session.add(context)
    return context


async def revoke_tokens_for_principal(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    principal_id: uuid.UUID,
    actor: str,
    reason: str,
) -> int:
    """Отозвать все действующие credentials Principal.

    Вызывается при disable Principal и предназначена для deprovisioning
    (SCIM, IAM-5): отзыв не зависит от того, кто инициировал отключение.
    Коммит остаётся за вызывающим кодом.
    """

    credentials = list(
        await session.scalars(
            select(PlatformAccessToken).where(
                PlatformAccessToken.tenant_id == tenant_id,
                PlatformAccessToken.principal_id == principal_id,
                PlatformAccessToken.revoked_at.is_(None),
            )
        )
    )
    revoked_at = _now()
    for credential in credentials:
        credential.revoked_at = revoked_at
        credential.revoked_by = actor
        credential.revoke_reason = reason
        session.add(
            OutboxEvent(
                tenant_id=tenant_id,
                type="credential.revoked",
                aggregate_type="platform_access_token",
                aggregate_id=credential.id,
                payload={**_credential_payload(credential), "reason": reason},
            )
        )
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action="platform_access_tokens.revoke",
                actor_ref=actor,
                resource_type="platform_access_token",
                resource_id=credential.id,
                outcome="allowed",
                reason=f"pat:{credential.public_prefix} reason:{reason}",
            )
        )
    return len(credentials)


def create_platform_token_router(
    *,
    settings: Settings,
    get_session: Callable[..., Any],
    require_bootstrap: Callable[..., Any],
) -> APIRouter:
    router = APIRouter()

    def token_issuer() -> TokenIssuer:
        return TokenIssuer(
            issuer=settings.issuer,
            private_key=settings.resolved_signing_private_key(),
            key_id=settings.signing_key_id,
            ttl_seconds=settings.token_ttl_seconds,
        )

    async def active_member(
        session: AsyncSession, tenant_id: uuid.UUID, principal_id: uuid.UUID
    ) -> Principal:
        tenant = await session.get(Tenant, tenant_id)
        if tenant is None or tenant.status != "active":
            raise HTTPException(status_code=404, detail="tenant_not_found")
        principal = await session.scalar(
            select(Principal)
            .join(TenantMembership, TenantMembership.principal_id == Principal.id)
            .where(
                TenantMembership.tenant_id == tenant_id,
                TenantMembership.principal_id == principal_id,
                TenantMembership.status == "active",
            )
        )
        if principal is None:
            raise HTTPException(status_code=404, detail="principal_not_found")
        if principal.status != "active":
            raise HTTPException(status_code=409, detail="principal_not_active")
        return principal

    async def known_audiences(
        session: AsyncSession, tenant_id: uuid.UUID, keys: list[str]
    ) -> dict[str, Audience]:
        rows = await session.scalars(
            select(Audience).where(
                Audience.tenant_id == tenant_id,
                Audience.status == "active",
                Audience.key.in_(keys),
            )
        )
        found = {row.key: row for row in rows}
        if set(found) != set(keys):
            raise HTTPException(status_code=422, detail="unknown_audience")
        return found

    async def authentication_snapshot(
        session: AsyncSession, tenant_id: uuid.UUID, principal: Principal
    ) -> dict[str, Any]:
        """Снимок свежей human authentication, обязательный для выпуска PAT.

        Без подтверждённого входа выпуск невозможен: token не должен
        появляться вне человеческой аутентификации (ADR-0012). Свежесть
        считается по серверному `recorded_at`, поэтому старую upstream-сессию
        нельзя выдать за новую, подставив `auth_time`.
        """

        context = await session.scalar(
            select(AuthenticationContext)
            .where(
                AuthenticationContext.tenant_id == tenant_id,
                AuthenticationContext.principal_id == principal.id,
            )
            .order_by(AuthenticationContext.recorded_at.desc())
        )
        recorded_at = _as_aware(context.recorded_at) if context else None
        if context is None or recorded_at is None:
            raise HTTPException(status_code=403, detail="authentication_context_required")
        if (_now() - recorded_at).total_seconds() > settings.pat_max_authentication_age_seconds:
            raise HTTPException(status_code=403, detail="authentication_context_expired")
        auth_time = _as_aware(context.auth_time) or recorded_at
        return {
            "authenticationContextId": str(context.id),
            "issuer": context.issuer,
            "acr": context.acr,
            "amr": list(context.amr),
            "authTime": auth_time.isoformat(),
        }

    async def replayed(
        session: AsyncSession, tenant_id: uuid.UUID, idempotency_key: str
    ) -> PlatformAccessToken | None:
        return await session.scalar(
            select(PlatformAccessToken).where(
                PlatformAccessToken.tenant_id == tenant_id,
                PlatformAccessToken.idempotency_key == idempotency_key,
            )
        )

    def issued(credential: PlatformAccessToken, token: str | None) -> PlatformAccessTokenIssued:
        return PlatformAccessTokenIssued(
            credential=PlatformAccessTokenView.model_validate(credential), token=token
        )

    @router.post(
        "/api/v1/tenants/{tenant_id}/principals/{principal_id}/authentication-contexts",
        response_model=AuthenticationContextView,
        status_code=201,
        tags=["platform-access-tokens"],
    )
    async def create_authentication_context(
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        body: AuthenticationContextRecord,
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> AuthenticationContext:
        """Зарегистрировать подтверждённый human authentication.

        Штатный производитель записи — federation-вход, вызывающий
        `record_authentication_context` внутри своей транзакции. Этот endpoint
        закрывает bootstrap и эксплуатационные сценарии.
        """

        principal = await active_member(session, tenant_id, principal_id)
        if principal.kind != "human":
            raise HTTPException(status_code=422, detail="human_principal_required")
        context = record_authentication_context(
            session,
            tenant_id=tenant_id,
            principal_id=principal.id,
            issuer=body.issuer,
            acr=body.acr,
            amr=body.amr,
            auth_time=body.auth_time,
            external_identity_id=body.external_identity_id,
            source="bootstrap",
        )
        await session.flush()
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action="authentication_contexts.record",
                actor_ref=actor,
                resource_type="authentication_context",
                resource_id=context.id,
                outcome="allowed",
                reason=f"principal:{principal.id} acr:{context.acr or 'none'}",
            )
        )
        await session.commit()
        return context

    @router.post(
        "/api/v1/tenants/{tenant_id}/principals/{principal_id}/platform-access-tokens",
        response_model=PlatformAccessTokenIssued,
        status_code=201,
        tags=["platform-access-tokens"],
    )
    async def issue_platform_access_token(
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        body: PlatformAccessTokenCreate,
        response: Response,
        idempotency_key: str = Header(default="", alias="Idempotency-Key"),
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> PlatformAccessTokenIssued:
        if not idempotency_key:
            raise HTTPException(status_code=400, detail="idempotency_key_required")
        existing = await replayed(session, tenant_id, idempotency_key)
        if existing is not None:
            response.headers["Idempotency-Replayed"] = "true"
            return issued(existing, None)

        principal = await active_member(session, tenant_id, principal_id)
        if principal.kind != "human":
            raise HTTPException(status_code=422, detail="human_principal_required")
        context = await authentication_snapshot(session, tenant_id, principal)
        audiences = sorted(set(body.audiences))
        resolved = await known_audiences(session, tenant_id, audiences)
        ceiling = sorted(set(body.scope_ceiling))
        permitted = {scope for row in resolved.values() for scope in row.allowed_scopes}
        if not set(ceiling).issubset(permitted):
            raise HTTPException(status_code=422, detail="invalid_scope_ceiling")
        ttl = body.expires_in_seconds or settings.pat_default_ttl_seconds
        if ttl > settings.pat_max_ttl_seconds:
            raise HTTPException(status_code=422, detail="expiry_too_long")

        material = generate_platform_access_token()
        credential = PlatformAccessToken(
            tenant_id=tenant_id,
            principal_id=principal.id,
            name=body.name,
            kind=KIND_PLATFORM_ACCESS_TOKEN,
            public_prefix=material.public_prefix,
            secret_hash=material.secret_hash,
            audiences=audiences,
            scope_ceiling=ceiling,
            authentication_context=context,
            idempotency_key=idempotency_key,
            expires_at=_now() + timedelta(seconds=ttl),
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
                    payload=_credential_payload(credential),
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="platform_access_tokens.issue",
                    actor_ref=actor,
                    resource_type="platform_access_token",
                    resource_id=credential.id,
                    outcome="allowed",
                    reason=f"pat:{credential.public_prefix} principal:{principal.id}",
                )
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            concurrent = await replayed(session, tenant_id, idempotency_key)
            if concurrent is None:
                raise HTTPException(status_code=409, detail="credential_conflict") from exc
            response.headers["Idempotency-Replayed"] = "true"
            return issued(concurrent, None)
        return issued(credential, material.full_token)

    @router.get(
        "/api/v1/tenants/{tenant_id}/platform-access-tokens",
        response_model=list[PlatformAccessTokenView],
        tags=["platform-access-tokens"],
    )
    async def list_platform_access_tokens(
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID | None = Query(default=None, alias="principalId"),
        include_revoked: bool = Query(default=False, alias="includeRevoked"),
        _: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> list[PlatformAccessToken]:
        statement = select(PlatformAccessToken).where(PlatformAccessToken.tenant_id == tenant_id)
        if principal_id is not None:
            statement = statement.where(PlatformAccessToken.principal_id == principal_id)
        if not include_revoked:
            statement = statement.where(PlatformAccessToken.revoked_at.is_(None))
        return list(await session.scalars(statement.order_by(PlatformAccessToken.created_at)))

    @router.post(
        "/api/v1/tenants/{tenant_id}/platform-access-tokens/{credential_id}:revoke",
        status_code=204,
        tags=["platform-access-tokens"],
    )
    async def revoke_platform_access_token(
        tenant_id: uuid.UUID,
        credential_id: uuid.UUID,
        reason: str = Query(default="revoked", max_length=200),
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        credential = await session.scalar(
            select(PlatformAccessToken).where(
                PlatformAccessToken.tenant_id == tenant_id,
                PlatformAccessToken.id == credential_id,
            )
        )
        if credential is None:
            raise HTTPException(status_code=404, detail="credential_not_found")
        if credential.revoked_at is None:
            credential.revoked_at = _now()
            credential.revoked_by = actor
            credential.revoke_reason = reason
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="credential.revoked",
                    aggregate_type="platform_access_token",
                    aggregate_id=credential.id,
                    payload={**_credential_payload(credential), "reason": reason},
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="platform_access_tokens.revoke",
                    actor_ref=actor,
                    resource_type="platform_access_token",
                    resource_id=credential.id,
                    outcome="allowed",
                    reason=f"pat:{credential.public_prefix} reason:{reason}",
                )
            )
            await session.commit()
        return Response(status_code=204)

    @router.post(
        "/api/v1/tenants/{tenant_id}/platform-access-tokens/{credential_id}:rotate",
        response_model=PlatformAccessTokenIssued,
        status_code=201,
        tags=["platform-access-tokens"],
    )
    async def rotate_platform_access_token(
        tenant_id: uuid.UUID,
        credential_id: uuid.UUID,
        body: PlatformAccessTokenRotate,
        response: Response,
        idempotency_key: str = Header(default="", alias="Idempotency-Key"),
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> PlatformAccessTokenIssued:
        if not idempotency_key:
            raise HTTPException(status_code=400, detail="idempotency_key_required")
        existing = await replayed(session, tenant_id, idempotency_key)
        if existing is not None:
            response.headers["Idempotency-Replayed"] = "true"
            return issued(existing, None)

        previous = await session.scalar(
            select(PlatformAccessToken).where(
                PlatformAccessToken.tenant_id == tenant_id,
                PlatformAccessToken.id == credential_id,
            )
        )
        if previous is None:
            raise HTTPException(status_code=404, detail="credential_not_found")
        expires_at = _as_aware(previous.expires_at)
        if previous.revoked_at is not None or expires_at is None or expires_at <= _now():
            raise HTTPException(status_code=409, detail="credential_not_active")
        await active_member(session, tenant_id, previous.principal_id)

        material = generate_platform_access_token()
        successor = PlatformAccessToken(
            tenant_id=tenant_id,
            principal_id=previous.principal_id,
            name=previous.name,
            kind=previous.kind,
            public_prefix=material.public_prefix,
            secret_hash=material.secret_hash,
            audiences=list(previous.audiences),
            scope_ceiling=list(previous.scope_ceiling),
            authentication_context=dict(previous.authentication_context),
            idempotency_key=idempotency_key,
            rotated_from_id=previous.id,
            # Ротация меняет только секрет: окно жизни наследуется и не продлевается.
            expires_at=expires_at,
        )
        previous.revoked_at = _now()
        previous.revoked_by = actor
        previous.revoke_reason = "rotated"
        session.add(successor)
        try:
            await session.flush()
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="platform_access_token.rotated",
                    aggregate_type="platform_access_token",
                    aggregate_id=successor.id,
                    payload={
                        **_credential_payload(successor),
                        "rotatedFromId": str(previous.id),
                        "rotatedFromPrefix": previous.public_prefix,
                    },
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="platform_access_tokens.rotate",
                    actor_ref=actor,
                    resource_type="platform_access_token",
                    resource_id=successor.id,
                    outcome="allowed",
                    reason=f"pat:{successor.public_prefix} rotated_from:{previous.public_prefix}",
                )
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            concurrent = await replayed(session, tenant_id, idempotency_key)
            if concurrent is None:
                raise HTTPException(status_code=409, detail="credential_conflict") from exc
            response.headers["Idempotency-Replayed"] = "true"
            return issued(concurrent, None)
        return issued(successor, material.full_token)

    @router.post(
        "/api/v1/tenants/{tenant_id}/legacy-credentials:import",
        response_model=PlatformAccessTokenView,
        status_code=201,
        tags=["platform-access-tokens"],
    )
    async def import_legacy_credential(
        tenant_id: uuid.UUID,
        body: LegacyCredentialImport,
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> PlatformAccessToken:
        """Compatibility mapping текущего Control Plane API key.

        Переносится только `(key_prefix, key_hash)`: hash-функция у обоих
        сервисов одна, поэтому владелец ключа продолжает предъявлять его как
        есть, а IAM никогда не видит открытый секрет. Окно совместимости
        обязательно ограничено сроком.
        """

        if not is_valid_prefix(body.key_prefix) or not is_valid_hash(body.key_hash):
            raise HTTPException(status_code=422, detail="invalid_credential_material")
        if body.expires_in_seconds > settings.legacy_credential_max_ttl_seconds:
            raise HTTPException(status_code=422, detail="compatibility_window_too_long")
        await active_member(session, tenant_id, body.principal_id)
        resolved = await known_audiences(session, tenant_id, [body.audience])
        ceiling = sorted(set(body.scope_ceiling))
        if not set(ceiling).issubset(resolved[body.audience].allowed_scopes):
            raise HTTPException(status_code=422, detail="invalid_scope_ceiling")

        credential = PlatformAccessToken(
            tenant_id=tenant_id,
            principal_id=body.principal_id,
            name=body.name,
            kind=KIND_LEGACY_CONTROL_PLANE_API_KEY,
            public_prefix=body.key_prefix,
            secret_hash=body.key_hash,
            audiences=[body.audience],
            scope_ceiling=ceiling,
            authentication_context={"source": "control_plane_api_key_migration"},
            expires_at=_now() + timedelta(seconds=body.expires_in_seconds),
        )
        session.add(credential)
        try:
            await session.flush()
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="legacy_credential.imported",
                    aggregate_type="platform_access_token",
                    aggregate_id=credential.id,
                    payload=_credential_payload(credential),
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="legacy_credentials.import",
                    actor_ref=actor,
                    resource_type="platform_access_token",
                    resource_id=credential.id,
                    outcome="allowed",
                    reason=f"legacy:{credential.public_prefix}",
                )
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail="credential_exists") from exc
        return credential

    @router.post(
        "/api/v1/tenants/{tenant_id}/principals/{principal_id}:disable",
        response_model=PrincipalDisabled,
        tags=["platform-access-tokens"],
    )
    async def disable_principal(
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        reason: str = Query(default="principal_disabled", max_length=200),
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> PrincipalDisabled:
        """Отключение Principal с отзывом всех его credentials.

        Тот же путь используется deprovisioning: выпуск новых credentials
        прекращается, а уже выданные PAT перестают обмениваться немедленно.
        """

        principal = await session.scalar(
            select(Principal)
            .join(TenantMembership, TenantMembership.principal_id == Principal.id)
            .where(
                TenantMembership.tenant_id == tenant_id,
                TenantMembership.principal_id == principal_id,
            )
        )
        if principal is None:
            raise HTTPException(status_code=404, detail="principal_not_found")
        principal.status = "disabled"
        revoked = await revoke_tokens_for_principal(
            session,
            tenant_id=tenant_id,
            principal_id=principal_id,
            actor=actor,
            reason=reason,
        )
        session.add(
            OutboxEvent(
                tenant_id=tenant_id,
                type="principal.disabled",
                aggregate_type="principal",
                aggregate_id=principal.id,
                payload={"principalId": str(principal.id), "revokedCredentials": revoked},
            )
        )
        await session.commit()
        return PrincipalDisabled(
            principal_id=principal.id, status=principal.status, revoked_credentials=revoked
        )

    @router.post(
        "/api/v1/platform-access-tokens:exchange",
        response_model=PlatformTokenExchangeResponse,
        tags=["platform-access-tokens"],
    )
    async def exchange_platform_access_token(
        body: PlatformTokenExchangeRequest,
        session: AsyncSession = Depends(get_session),
    ) -> PlatformTokenExchangeResponse:
        """Обменять PAT на короткоживущий credential одного audience.

        Tenant и Principal берутся из записи токена, а не из запроса: клиент
        не может объявить чужой tenant. Выдаваемый token содержит identity и
        ограничения authority — и ни одного entitlement или доменного права.
        """

        presented = parse_presented_credential(body.token)
        credential = None
        if presented is not None:
            credential = await session.scalar(
                select(PlatformAccessToken).where(
                    PlatformAccessToken.public_prefix == presented.public_prefix,
                    PlatformAccessToken.kind == presented.kind,
                )
            )
        # Хэш считается всегда, в том числе для несуществующего prefix.
        stored_hash = credential.secret_hash if credential is not None else _ABSENT_HASH
        if not matches_stored_hash(body.token, stored_hash) or credential is None:
            raise HTTPException(status_code=401, detail=_INVALID_TOKEN)

        async def deny(status_code: int, detail: str, reason: str) -> HTTPException:
            session.add(
                AuditEvent(
                    tenant_id=credential.tenant_id,
                    action="platform_access_tokens.exchange",
                    actor_ref=str(credential.principal_id),
                    resource_type="platform_access_token",
                    resource_id=credential.id,
                    outcome="denied",
                    reason=f"pat:{credential.public_prefix} {reason}",
                )
            )
            await session.commit()
            return HTTPException(status_code=status_code, detail=detail)

        expires_at = _as_aware(credential.expires_at)
        if credential.revoked_at is not None:
            raise await deny(401, _INVALID_TOKEN, "credential_revoked")
        if expires_at is None or expires_at <= _now():
            raise await deny(401, _INVALID_TOKEN, "credential_expired")

        tenant = await session.get(Tenant, credential.tenant_id)
        membership = await session.get(
            TenantMembership,
            {"tenant_id": credential.tenant_id, "principal_id": credential.principal_id},
        )
        principal = await session.get(Principal, credential.principal_id)
        if tenant is None or tenant.status != "active":
            raise await deny(401, _INVALID_TOKEN, "tenant_not_active")
        if membership is None or membership.status != "active":
            raise await deny(401, _INVALID_TOKEN, "membership_not_active")
        if principal is None or principal.status != "active":
            raise await deny(401, _INVALID_TOKEN, "principal_not_active")

        if body.audience not in credential.audiences:
            raise await deny(403, "audience_not_allowed", f"audience:{body.audience}")
        audience = await session.scalar(
            select(Audience).where(
                Audience.tenant_id == credential.tenant_id,
                Audience.key == body.audience,
                Audience.status == "active",
            )
        )
        if audience is None:
            raise await deny(403, "audience_not_allowed", f"audience:{body.audience}")

        ceiling = set(credential.scope_ceiling)
        allowed = set(audience.allowed_scopes)
        requested = set(body.scopes)
        if requested and not requested.issubset(ceiling & allowed):
            raise await deny(403, "scope_not_allowed", f"audience:{body.audience}")
        # Пустой запрос означает «весь потолок», но потолок всё равно
        # пересекается с тем, что вообще разрешено audience.
        effective = sorted(requested or (ceiling & allowed))

        session_id = uuid.uuid4()
        context = credential.authentication_context or {}
        token = token_issuer().issue(
            subject=credential.principal_id,
            tenant_id=credential.tenant_id,
            audience=body.audience,
            scopes=effective,
            credential_id=credential.id,
            principal_type=principal.kind,
            scope_ceiling=sorted(ceiling),
            session_id=session_id,
            auth_time=context.get("authTime"),
            acr=context.get("acr"),
        )
        credential.last_used_at = _now()
        session.add(
            AuditEvent(
                tenant_id=credential.tenant_id,
                action="platform_access_tokens.exchange",
                actor_ref=str(credential.principal_id),
                resource_type="platform_access_token",
                resource_id=credential.id,
                outcome="allowed",
                reason=(
                    f"pat:{credential.public_prefix} audience:{body.audience} session:{session_id}"
                ),
            )
        )
        await session.commit()
        return PlatformTokenExchangeResponse(
            access_token=token,
            expires_in=settings.token_ttl_seconds,
            audience=body.audience,
            scope=effective,
            session_id=session_id,
        )

    return router
