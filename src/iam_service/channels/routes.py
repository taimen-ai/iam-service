"""Канал (Telegram) как способ входа человека.

Три шага и три разных предъявителя:

1. человек со своим токеном IAM (`aud = IAM_CHANNEL_AUDIENCE`) просит код
   привязки — `POST …/channel-link-intents`;
2. адаптер канала (service account со scope `iam:channel-links`) приносит код,
   который человек прислал боту, и id его аккаунта — `POST
   …/channel-links:confirm`; появляется `ExternalIdentity` с `source='channel'`;
3. когда человек отвечает на уведомление в канале, адаптер обменивает
   assertion «этот аккаунт сейчас решил» на token одного решения — `POST
   …/channel-assertions:exchange`: `principal_type=human`,
   `acr=channel:<канал>`, один audience, один scope, `purpose_ref`, минута
   жизни.

Каждый отказ пишется в audit с точной причиной, наружу уходит код без
подробностей там, где подробность работала бы оракулом (код привязки).
Лимиты частоты считаются по той же базе, поэтому переживают рестарт и
работают на нескольких репликах.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from iam_service.channels.models import CHANNELS, ChannelLinkIntent, ChannelProvider
from iam_service.channels.schemas import (
    ChannelAssertionExchange,
    ChannelAssertionToken,
    ChannelLinkConfirm,
    ChannelLinkIntentCreate,
    ChannelLinkIntentIssued,
    ChannelLinkView,
    ChannelProviderUpdate,
    ChannelProviderView,
)
from iam_service.config import Settings
from iam_service.models import (
    Audience,
    AuditEvent,
    ExternalIdentity,
    OutboxEvent,
    Principal,
    ServiceAccount,
    Tenant,
    TenantMembership,
)
from iam_service.tokens import TokenIssuer, verify_access_token

# Формат id аккаунта по каналу. Telegram user id — целое число.
_SUBJECT_FORMAT = {"telegram": re.compile(r"^[0-9]{1,20}$")}
# Префикс `acr` токенов, выданных по assertion канала. Такой token не может
# сам открыть новую привязку: иначе захваченный канал размножал бы себя.
_CHANNEL_ACR_PREFIX = "channel:"


def _now() -> datetime:
    return datetime.now(UTC)


def _as_aware(value: datetime | None) -> datetime | None:
    """SQLite отдаёт naive datetime; сравнения ведём в UTC."""

    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _parse_time(raw: object) -> datetime | None:
    if isinstance(raw, int | float):
        return datetime.fromtimestamp(float(raw), tz=UTC)
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return _as_aware(datetime.fromisoformat(raw))
    except ValueError:
        return None


def _subject(claims: dict[str, Any]) -> uuid.UUID:
    try:
        return uuid.UUID(str(claims.get("sub")))
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid_token") from exc


def channel_issuer(tenant_id: uuid.UUID, channel: str) -> str:
    """Issuer привязок канала.

    Пара `issuer + subject` уникальна глобально, а аккаунт канала глобален
    (один Telegram user id во всех tenant). Tenant в issuer держит привязки
    разных tenant независимыми и не даёт им сталкиваться.
    """

    return f"iam:channel:{channel}:{tenant_id}"


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def _link_view(identity: ExternalIdentity, channel: str) -> ChannelLinkView:
    return ChannelLinkView(
        linkId=identity.id,
        principalId=identity.principal_id,
        channel=channel,
        status=identity.status,
        linkedAt=identity.created_at,
        lastUsedAt=identity.last_authenticated_at,
    )


def create_channel_router(
    *,
    settings: Settings,
    get_session: Callable[..., Any],
    require_bootstrap: Callable[..., Any],
) -> APIRouter:
    router = APIRouter(tags=["channels"])

    def token_issuer() -> TokenIssuer:
        return TokenIssuer(
            issuer=settings.issuer,
            private_key=settings.resolved_signing_private_key(),
            key_id=settings.signing_key_id,
            ttl_seconds=settings.token_ttl_seconds,
        )

    def verified_claims(authorization: str, tenant_id: uuid.UUID) -> dict[str, Any]:
        """Проверить bearer для audience IAM и сверить tenant с путём."""

        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise HTTPException(status_code=401, detail="invalid_token")
        try:
            claims = verify_access_token(
                token.strip(),
                public_key=token_issuer().private_key.public_key(),
                issuer=settings.issuer,
                audience=settings.channel_audience,
            )
        except Exception as exc:
            raise HTTPException(status_code=401, detail="invalid_token") from exc
        # Tenant из пути авторитетным не бывает: только из подписанного token.
        if claims.get("tenant_id") != str(tenant_id):
            raise HTTPException(status_code=403, detail="tenant_mismatch")
        return claims

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
        headers: dict[str, str] | None = None,
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
        return HTTPException(status_code=status_code, detail=detail, headers=headers)

    async def recent_audit(
        session: AsyncSession,
        *,
        tenant_id: uuid.UUID,
        action: str,
        window_seconds: int,
        outcome: str,
        actor_ref: str | None = None,
        resource_id: uuid.UUID | None = None,
    ) -> int:
        query = select(func.count()).where(
            AuditEvent.tenant_id == tenant_id,
            AuditEvent.action == action,
            AuditEvent.outcome == outcome,
            AuditEvent.occurred_at >= _now() - timedelta(seconds=window_seconds),
        )
        if actor_ref is not None:
            query = query.where(AuditEvent.actor_ref == actor_ref)
        if resource_id is not None:
            query = query.where(AuditEvent.resource_id == resource_id)
        return int(await session.scalar(query) or 0)

    async def active_provider(
        session: AsyncSession, tenant_id: uuid.UUID, channel: str
    ) -> ChannelProvider | None:
        return await session.scalar(
            select(ChannelProvider).where(
                ChannelProvider.tenant_id == tenant_id,
                ChannelProvider.channel == channel,
                ChannelProvider.status == "active",
            )
        )

    async def active_principal(
        session: AsyncSession, tenant_id: uuid.UUID, principal_id: uuid.UUID
    ) -> Principal | None:
        return await session.scalar(
            select(Principal)
            .join(TenantMembership, TenantMembership.principal_id == Principal.id)
            .where(
                TenantMembership.tenant_id == tenant_id,
                TenantMembership.principal_id == principal_id,
                TenantMembership.status == "active",
                Principal.status == "active",
            )
        )

    async def human_caller(
        tenant_id: uuid.UUID,
        authorization: str = Header(default=""),
        session: AsyncSession = Depends(get_session),
    ) -> tuple[Principal, dict[str, Any]]:
        """Человек со своим токеном IAM — и только человек.

        Токен, выданный по assertion канала, сюда не проходит: привязку нового
        способа входа открывает только полноценный вход, а не сам канал.
        """

        claims = verified_claims(authorization, tenant_id)
        principal_id = _subject(claims)
        action = "channel_links.authenticate"
        if claims.get("principal_type") != "human":
            raise await refuse(
                session,
                tenant_id=tenant_id,
                action=action,
                actor_ref=str(principal_id),
                resource_type="principal",
                resource_id=principal_id,
                status_code=403,
                detail="human_principal_required",
                reason=f"principal_type:{claims.get('principal_type')}",
            )
        if str(claims.get("acr") or "").startswith(_CHANNEL_ACR_PREFIX):
            raise await refuse(
                session,
                tenant_id=tenant_id,
                action=action,
                actor_ref=str(principal_id),
                resource_type="principal",
                resource_id=principal_id,
                status_code=403,
                detail="channel_authentication_not_allowed",
            )
        principal = await active_principal(session, tenant_id, principal_id)
        if principal is None or principal.kind != "human":
            raise await refuse(
                session,
                tenant_id=tenant_id,
                action=action,
                actor_ref=str(principal_id),
                resource_type="principal",
                resource_id=principal_id,
                status_code=403,
                detail="principal_not_active",
            )
        return principal, claims

    async def channel_adapter(
        tenant_id: uuid.UUID,
        authorization: str = Header(default=""),
        session: AsyncSession = Depends(get_session),
    ) -> ServiceAccount:
        """Адаптер канала: confidential service account со scope канала."""

        claims = verified_claims(authorization, tenant_id)
        if claims.get("principal_type") != "service_account":
            raise HTTPException(status_code=403, detail="service_account_required")
        if settings.channel_scope not in set(claims.get("scope") or []):
            raise HTTPException(status_code=403, detail="scope_not_granted")
        # Отзыв service account действует сразу, не дожидаясь истечения его
        # token: assertion канала — это выпуск credential человека.
        try:
            credential_id = uuid.UUID(str(claims.get("credential_id")))
        except ValueError as exc:
            raise HTTPException(status_code=401, detail="invalid_token") from exc
        account = await session.scalar(
            select(ServiceAccount).where(
                ServiceAccount.id == credential_id,
                ServiceAccount.tenant_id == tenant_id,
                ServiceAccount.principal_id == _subject(claims),
                ServiceAccount.revoked_at.is_(None),
            )
        )
        if account is None:
            raise HTTPException(status_code=401, detail="invalid_token")
        return account

    # --- провайдер per tenant ------------------------------------------

    @router.put(
        "/api/v1/tenants/{tenant_id}/channel-providers/{channel}",
        response_model=ChannelProviderView,
    )
    async def configure_channel_provider(
        tenant_id: uuid.UUID,
        body: ChannelProviderUpdate,
        channel: str = Path(pattern=r"^(telegram)$"),
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> ChannelProviderView:
        """Включить или выключить канал как способ входа в tenant.

        Выключение сразу закрывает подтверждение привязок и обмен assertion;
        сами привязки остаются и снова работают после включения.
        """

        if await session.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        provider = await session.scalar(
            select(ChannelProvider).where(
                ChannelProvider.tenant_id == tenant_id, ChannelProvider.channel == channel
            )
        )
        if provider is None:
            provider = ChannelProvider(tenant_id=tenant_id, channel=channel, status=body.status)
            session.add(provider)
        elif provider.status == body.status:
            return ChannelProviderView(
                channel=provider.channel, status=provider.status, updatedAt=provider.updated_at
            )
        provider.status = body.status
        provider.updated_at = _now()
        await session.flush()
        session.add(
            OutboxEvent(
                tenant_id=tenant_id,
                type="channel_provider.updated",
                aggregate_type="channel_provider",
                aggregate_id=provider.id,
                payload={
                    "channelProviderId": str(provider.id),
                    "channel": channel,
                    "status": body.status,
                },
            )
        )
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action="channel_providers.update",
                actor_ref=actor,
                resource_type="channel_provider",
                resource_id=provider.id,
                outcome="allowed",
                reason=f"channel:{channel} status:{body.status}",
            )
        )
        view = ChannelProviderView(
            channel=provider.channel, status=provider.status, updatedAt=provider.updated_at
        )
        await session.commit()
        return view

    @router.get(
        "/api/v1/tenants/{tenant_id}/channel-providers",
        response_model=list[ChannelProviderView],
    )
    async def list_channel_providers(
        tenant_id: uuid.UUID,
        _: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> list[ChannelProviderView]:
        rows = await session.scalars(
            select(ChannelProvider)
            .where(ChannelProvider.tenant_id == tenant_id)
            .order_by(ChannelProvider.channel)
        )
        return [
            ChannelProviderView(channel=row.channel, status=row.status, updatedAt=row.updated_at)
            for row in rows
        ]

    # --- привязка -------------------------------------------------------

    @router.post(
        "/api/v1/tenants/{tenant_id}/channel-link-intents",
        response_model=ChannelLinkIntentIssued,
        status_code=201,
    )
    async def create_channel_link_intent(
        tenant_id: uuid.UUID,
        body: ChannelLinkIntentCreate,
        caller: tuple[Principal, dict[str, Any]] = Depends(human_caller),
        session: AsyncSession = Depends(get_session),
    ) -> ChannelLinkIntentIssued:
        """Выдать человеку одноразовый код привязки аккаунта канала."""

        principal, claims = caller
        principal_id = principal.id
        action = "channel_link_intents.create"

        async def deny(status_code: int, detail: str, **extra: Any) -> HTTPException:
            return await refuse(
                session,
                tenant_id=tenant_id,
                action=action,
                actor_ref=str(principal_id),
                resource_type="principal",
                resource_id=principal_id,
                status_code=status_code,
                detail=detail,
                reason=f"channel:{body.channel} {detail}",
                **extra,
            )

        if await active_provider(session, tenant_id, body.channel) is None:
            raise await deny(403, "channel_provider_disabled")
        # Новый способ входа привязывается только при свежем входе: украденный
        # старый token не должен открывать атакующему постоянный канал.
        auth_time = _parse_time(claims.get("auth_time"))
        max_age = settings.channel_link_max_authentication_age_seconds
        if auth_time is None or (_now() - auth_time).total_seconds() > max_age:
            raise await deny(403, "authentication_context_expired")
        issued = int(
            await session.scalar(
                select(func.count()).where(
                    ChannelLinkIntent.tenant_id == tenant_id,
                    ChannelLinkIntent.principal_id == principal_id,
                    ChannelLinkIntent.created_at
                    >= _now() - timedelta(seconds=settings.channel_link_intent_window_seconds),
                )
            )
            or 0
        )
        if issued >= settings.channel_link_intent_limit:
            raise await deny(
                429,
                "rate_limited",
                headers={"Retry-After": str(settings.channel_link_intent_window_seconds)},
            )
        existing = await session.scalar(
            select(ExternalIdentity.id).where(
                ExternalIdentity.issuer == channel_issuer(tenant_id, body.channel),
                ExternalIdentity.principal_id == principal_id,
                ExternalIdentity.source == "channel",
                ExternalIdentity.status == "active",
            )
        )
        if existing is not None:
            raise await deny(409, "channel_already_linked")

        code = secrets.token_urlsafe(24)
        now = _now()
        intent = ChannelLinkIntent(
            tenant_id=tenant_id,
            principal_id=principal_id,
            channel=body.channel,
            code_hash=_hash_code(code),
            created_at=now,
            expires_at=now + timedelta(seconds=settings.channel_link_code_ttl_seconds),
        )
        session.add(intent)
        await session.flush()
        session.add(
            OutboxEvent(
                tenant_id=tenant_id,
                type="channel_link_intent.created",
                aggregate_type="channel_link_intent",
                aggregate_id=intent.id,
                payload={
                    "intentId": str(intent.id),
                    "principalId": str(principal_id),
                    "channel": body.channel,
                    "expiresAt": intent.expires_at.isoformat(),
                },
            )
        )
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action=action,
                actor_ref=str(principal_id),
                resource_type="channel_link_intent",
                resource_id=intent.id,
                outcome="allowed",
                reason=f"channel:{body.channel}",
            )
        )
        await session.commit()
        return ChannelLinkIntentIssued(
            intentId=intent.id, channel=body.channel, code=code, expiresAt=intent.expires_at
        )

    @router.post(
        "/api/v1/tenants/{tenant_id}/channel-links:confirm",
        response_model=ChannelLinkView,
    )
    async def confirm_channel_link(
        tenant_id: uuid.UUID,
        body: ChannelLinkConfirm,
        account: ServiceAccount = Depends(channel_adapter),
        session: AsyncSession = Depends(get_session),
    ) -> ChannelLinkView:
        """Привязать аккаунт канала по коду, который человек прислал боту.

        Неизвестный, чужой, просроченный и использованный код отвечают
        одинаково (`invalid_link_code`): точная причина — только в audit.
        """

        adapter_ref, account_id = str(account.principal_id), account.id
        action = "channel_links.confirm"

        async def deny(status_code: int, detail: str, reason: str = "", **extra: Any):
            return await refuse(
                session,
                tenant_id=tenant_id,
                action=action,
                actor_ref=adapter_ref,
                resource_type="service_account",
                resource_id=account_id,
                status_code=status_code,
                detail=detail,
                reason=f"channel:{body.channel} {reason or detail}",
                **extra,
            )

        failures = await recent_audit(
            session,
            tenant_id=tenant_id,
            action=action,
            outcome="denied",
            actor_ref=adapter_ref,
            window_seconds=settings.channel_confirm_failure_window_seconds,
        )
        if failures >= settings.channel_confirm_failure_limit:
            raise await deny(
                429,
                "rate_limited",
                headers={"Retry-After": str(settings.channel_confirm_failure_window_seconds)},
            )
        if await active_provider(session, tenant_id, body.channel) is None:
            raise await deny(403, "channel_provider_disabled")
        if not _SUBJECT_FORMAT[body.channel].match(body.external_subject):
            raise await deny(422, "invalid_external_subject")

        # Поиск по hash без tenant: код другого tenant находится, но
        # отклоняется как «чужой» — это видно в audit, но не снаружи.
        intent = await session.scalar(
            select(ChannelLinkIntent).where(ChannelLinkIntent.code_hash == _hash_code(body.code))
        )
        now = _now()
        if intent is None:
            raise await deny(400, "invalid_link_code", "code_unknown")
        if intent.tenant_id != tenant_id or intent.channel != body.channel:
            raise await deny(400, "invalid_link_code", "code_foreign")
        if intent.used_at is not None:
            raise await deny(400, "invalid_link_code", "code_used")
        if (_as_aware(intent.expires_at) or now) <= now:
            raise await deny(400, "invalid_link_code", "code_expired")

        principal = await active_principal(session, tenant_id, intent.principal_id)
        if principal is None:
            raise await deny(403, "principal_not_active")
        if principal.kind != "human":
            raise await deny(422, "human_principal_required", f"kind:{principal.kind}")

        issuer = channel_issuer(tenant_id, body.channel)
        other = await session.scalar(
            select(ExternalIdentity.id).where(
                ExternalIdentity.issuer == issuer,
                ExternalIdentity.principal_id == principal.id,
                ExternalIdentity.source == "channel",
                ExternalIdentity.status == "active",
                ExternalIdentity.subject != body.external_subject,
            )
        )
        if other is not None:
            raise await deny(409, "channel_already_linked")
        identity = await session.scalar(
            select(ExternalIdentity).where(
                ExternalIdentity.issuer == issuer,
                ExternalIdentity.subject == body.external_subject,
            )
        )
        if identity is not None and identity.source != "channel":
            raise await deny(409, "channel_account_linked", "identity_not_channel")
        if identity is not None and identity.status == "active":
            if identity.principal_id != principal.id:
                # Аккаунт уже привязан к другому человеку: сначала отзыв.
                raise await deny(409, "channel_account_linked")
        elif identity is not None:
            # Ранее отозванная привязка оживает для нового владельца. Её id
            # остаётся credential_id: закэшированный отзыв у resource service
            # в худшем случае закроет вход до истечения кэша, но не откроет.
            identity.principal_id = principal.id
            identity.status = "active"
            identity.created_at = now
            identity.last_authenticated_at = None
            identity.last_acr = None
        else:
            identity = ExternalIdentity(
                principal_id=principal.id,
                issuer=issuer,
                subject=body.external_subject,
                external_id=body.external_subject,
                source="channel",
                created_at=now,
            )
            session.add(identity)
        intent.used_at = now
        try:
            await session.flush()
            intent.external_identity_id = identity.id
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="channel_link.confirmed",
                    aggregate_type="external_identity",
                    aggregate_id=identity.id,
                    payload={
                        "linkId": str(identity.id),
                        "principalId": str(principal.id),
                        "channel": body.channel,
                    },
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action=action,
                    actor_ref=adapter_ref,
                    resource_type="external_identity",
                    resource_id=identity.id,
                    outcome="allowed",
                    reason=f"channel:{body.channel} principal:{principal.id} intent:{intent.id}",
                )
            )
            view = _link_view(identity, body.channel)
            await session.commit()
        except IntegrityError as exc:
            raise await deny(409, "channel_account_linked", "integrity_conflict") from exc
        return view

    @router.get(
        "/api/v1/tenants/{tenant_id}/channel-links",
        response_model=list[ChannelLinkView],
    )
    async def list_channel_links(
        tenant_id: uuid.UUID,
        caller: tuple[Principal, dict[str, Any]] = Depends(human_caller),
        session: AsyncSession = Depends(get_session),
    ) -> list[ChannelLinkView]:
        """Привязки каналов самого человека — чтобы было что отозвать."""

        principal, _ = caller
        issuers = {channel_issuer(tenant_id, channel): channel for channel in CHANNELS}
        rows = await session.scalars(
            select(ExternalIdentity)
            .where(
                ExternalIdentity.principal_id == principal.id,
                ExternalIdentity.source == "channel",
                ExternalIdentity.issuer.in_(issuers),
            )
            .order_by(ExternalIdentity.created_at)
        )
        return [_link_view(row, issuers[row.issuer]) for row in rows]

    @router.post(
        "/api/v1/tenants/{tenant_id}/channel-links/{link_id}:revoke",
        status_code=204,
    )
    async def revoke_channel_link(
        tenant_id: uuid.UUID,
        link_id: uuid.UUID,
        caller: tuple[Principal, dict[str, Any]] = Depends(human_caller),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        """Отвязать аккаунт канала. Следующий обмен assertion будет отклонён.

        Чужая привязка неотличима от несуществующей. Уже выданные токены
        живут не дольше `IAM_CHANNEL_ASSERTION_TTL_SECONDS`, а событие
        `channel_link.revoked` несёт `credentialId` для revocation-кэшей.
        """

        principal, _ = caller
        issuers = {channel_issuer(tenant_id, channel): channel for channel in CHANNELS}
        identity = await session.scalar(
            select(ExternalIdentity).where(
                ExternalIdentity.id == link_id,
                ExternalIdentity.principal_id == principal.id,
                ExternalIdentity.source == "channel",
                ExternalIdentity.issuer.in_(issuers),
            )
        )
        if identity is None:
            raise HTTPException(status_code=404, detail="channel_link_not_found")
        if identity.status == "active":
            channel = issuers[identity.issuer]
            identity.status = "disabled"
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="channel_link.revoked",
                    aggregate_type="external_identity",
                    aggregate_id=identity.id,
                    payload={
                        "linkId": str(identity.id),
                        "credentialId": str(identity.id),
                        "principalId": str(principal.id),
                        "channel": channel,
                    },
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="channel_links.revoke",
                    actor_ref=str(principal.id),
                    resource_type="external_identity",
                    resource_id=identity.id,
                    outcome="allowed",
                    reason=f"channel:{channel}",
                )
            )
            await session.commit()
        return Response(status_code=204)

    # --- обмен assertion ------------------------------------------------

    @router.post(
        "/api/v1/tenants/{tenant_id}/channel-assertions:exchange",
        response_model=ChannelAssertionToken,
    )
    async def exchange_channel_assertion(
        tenant_id: uuid.UUID,
        body: ChannelAssertionExchange,
        account: ServiceAccount = Depends(channel_adapter),
        session: AsyncSession = Depends(get_session),
    ) -> ChannelAssertionToken:
        """Обменять assertion канала на token одного решения человека.

        Узкий путь выдачи (конституция, ст. VI): audience и scope заданы
        конфигурацией, а не запросом; срок — минута; `purpose_ref` связывает
        token с предметом решения. `credential_id` — id привязки, поэтому её
        отзыв закрывает следующий обмен. Снимок authentication context для
        выпуска PAT не пишется: канал не открывает других способов входа.
        """

        adapter_ref, account_id = str(account.principal_id), account.id
        action = "channel_assertions.exchange"
        window = settings.channel_assertion_window_seconds

        async def deny(
            status_code: int,
            detail: str,
            *,
            resource: tuple[str, uuid.UUID] | None = None,
            **extra: Any,
        ) -> HTTPException:
            resource_type, resource_id = resource or ("service_account", account_id)
            return await refuse(
                session,
                tenant_id=tenant_id,
                action=action,
                actor_ref=adapter_ref,
                resource_type=resource_type,
                resource_id=resource_id,
                status_code=status_code,
                detail=detail,
                reason=f"channel:{body.channel} purpose:{body.purpose_ref} {detail}",
                **extra,
            )

        # Перебор аккаунтов тоже ограничен: отказы адаптера в окне.
        failures = await recent_audit(
            session,
            tenant_id=tenant_id,
            action=action,
            outcome="denied",
            actor_ref=adapter_ref,
            window_seconds=window,
        )
        if failures >= settings.channel_assertion_limit:
            raise await deny(429, "rate_limited", headers={"Retry-After": str(window)})
        if await active_provider(session, tenant_id, body.channel) is None:
            raise await deny(403, "channel_provider_disabled")

        identity = await session.scalar(
            select(ExternalIdentity).where(
                ExternalIdentity.issuer == channel_issuer(tenant_id, body.channel),
                ExternalIdentity.subject == body.external_subject,
                ExternalIdentity.source == "channel",
                ExternalIdentity.status == "active",
            )
        )
        if identity is None:
            raise await deny(404, "channel_account_not_linked")
        link = ("external_identity", identity.id)
        issued = await recent_audit(
            session,
            tenant_id=tenant_id,
            action=action,
            outcome="allowed",
            resource_id=identity.id,
            window_seconds=window,
        )
        if issued >= settings.channel_assertion_limit:
            raise await deny(
                429, "rate_limited", resource=link, headers={"Retry-After": str(window)}
            )
        principal = await active_principal(session, tenant_id, identity.principal_id)
        if principal is None:
            raise await deny(403, "principal_not_active", resource=link)
        if principal.kind != "human":
            raise await deny(422, "human_principal_required", resource=link)

        audience_key = settings.channel_assertion_audience
        scope = settings.channel_assertion_scope
        audience = await session.scalar(
            select(Audience).where(
                Audience.tenant_id == tenant_id,
                Audience.key == audience_key,
                Audience.status == "active",
            )
        )
        if audience is None:
            raise await deny(403, "audience_not_allowed", resource=link)
        if scope not in audience.allowed_scopes:
            raise await deny(403, "scope_not_allowed", resource=link)

        now = _now()
        acr = f"{_CHANNEL_ACR_PREFIX}{body.channel}"
        session_id = uuid.uuid4()
        ttl = min(settings.channel_assertion_ttl_seconds, settings.token_ttl_seconds)
        token = token_issuer().issue(
            subject=principal.id,
            tenant_id=tenant_id,
            audience=audience_key,
            scopes=[scope],
            credential_id=identity.id,
            principal_type="human",
            scope_ceiling=[scope],
            session_id=session_id,
            auth_time=now.isoformat(),
            acr=acr,
            amr=[acr],
            purpose_ref=body.purpose_ref,
            ttl_seconds=ttl,
        )
        identity.last_authenticated_at = now
        identity.last_acr = acr
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action=action,
                actor_ref=adapter_ref,
                resource_type="external_identity",
                resource_id=identity.id,
                outcome="allowed",
                reason=(
                    f"channel:{body.channel} principal:{principal.id} audience:{audience_key} "
                    f"purpose:{body.purpose_ref} session:{session_id}"
                ),
            )
        )
        principal_id = principal.id
        await session.commit()
        return ChannelAssertionToken(
            accessToken=token,
            expiresIn=ttl,
            audience=audience_key,
            scope=[scope],
            sessionId=session_id,
            principalId=principal_id,
            purposeRef=body.purpose_ref,
        )

    return router
