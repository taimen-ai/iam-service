from __future__ import annotations

import hmac
import secrets
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from iam_service.access_log import install_access_log_filter
from iam_service.agents import create_agent_router
from iam_service.channels import create_channel_router
from iam_service.config import Settings
from iam_service.db import Database
from iam_service.emails import EMAIL_MAX_LENGTH, normalize_email
from iam_service.federation import (
    FederationError,
    JsonFetcher,
    JwksResolver,
    ResolvedJwks,
    UpstreamClaims,
    ensure_authentication_context,
    project_groups,
    read_claims,
    verify_upstream_token,
)
from iam_service.federation.linking import (
    LinkedIdentity,
    link_identity,
    reconcile_group_projection,
    touch_authentication,
)
from iam_service.models import (
    Audience,
    AuditEvent,
    Base,
    ExternalIdentity,
    Group,
    GroupMember,
    IdentityProvider,
    OutboxEvent,
    Principal,
    ServiceAccount,
    Tenant,
    TenantMembership,
)
from iam_service.pat import create_platform_token_router, record_authentication_context
from iam_service.pat.models import AuthenticationContext, PlatformAccessToken
from iam_service.people import (
    Caller,
    create_people_guard,
    refuse,
    require_human_target,
)
from iam_service.people.connections import (
    CONNECTION_SOURCE,
    connection_issuer_tenant,
    is_connection_issuer,
    tenant_connection_prefix,
)
from iam_service.people.identities import create_identities_guard
from iam_service.privileged import entitled_privileged_scopes
from iam_service.schemas import (
    AudienceCreate,
    AudienceUpdate,
    AudienceView,
    EventPage,
    EventView,
    ExternalIdentityCreate,
    ExternalIdentityItem,
    ExternalIdentityPage,
    ExternalIdentityView,
    FederatedIdentityView,
    FederationAuthenticateRequest,
    FederationAuthenticationContext,
    FederationExchangeRequest,
    FederationExchangeResponse,
    GroupCreate,
    GroupMemberCreate,
    GroupMemberView,
    GroupView,
    IdentityProviderCreate,
    IdentityProviderView,
    PrincipalByEmailPage,
    PrincipalCreate,
    PrincipalPage,
    PrincipalView,
    ServiceAccountCreate,
    ServiceAccountIssued,
    ServiceAccountUpdate,
    ServiceAccountView,
    TenantCreate,
    TenantView,
    TokenExchangeRequest,
    TokenResponse,
)
from iam_service.scim import UpstreamTransport, create_scim_router
from iam_service.tokens import TokenIssuer


@dataclass
class FederationOutcome:
    """Результат подтверждённого federation-входа до commit.

    Собирает то, что обоим маршрутам нужно после linking: провайдера,
    состояние JWKS, upstream claims, связанную identity, проекцию групп и
    записанный снимок authentication context.
    """

    provider: IdentityProvider
    resolved: ResolvedJwks
    upstream: UpstreamClaims
    linked: LinkedIdentity
    groups: list[str]
    context: AuthenticationContext

    def authentication_context(self) -> FederationAuthenticationContext:
        return FederationAuthenticationContext(
            acr=self.upstream.context.acr,
            amr=list(self.upstream.context.amr),
            authTime=self.upstream.context.auth_time,
        )


def create_app(
    settings: Settings | None = None,
    *,
    jwks_fetcher: JsonFetcher | None = None,
    upstream_transport: UpstreamTransport | None = None,
) -> FastAPI:
    runtime_settings = settings or Settings()
    database = Database(runtime_settings)
    password_hasher = PasswordHasher()
    jwks_resolver = JwksResolver(jwks_fetcher)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if runtime_settings.create_schema_on_startup:
            async with database.engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
        yield
        await database.close()

    app = FastAPI(title="IAM Service", version="0.1.0", lifespan=lifespan)

    async def get_session() -> AsyncIterator[AsyncSession]:
        async for session in database.session():
            yield session

    def require_bootstrap(x_iam_bootstrap_token: str = Header(default="")) -> str:
        expected = runtime_settings.bootstrap_token
        if not expected or not hmac.compare_digest(x_iam_bootstrap_token, expected):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")
        return "bootstrap"

    # Маршруты principals принимают, кроме bootstrap, человека со `iam:people`.
    people_caller = create_people_guard(settings=runtime_settings, get_session=get_session)
    # Маршруты identity (ADR-0004) — ещё и агент со `iam:identities.link`.
    identities_caller = create_identities_guard(
        settings=runtime_settings, get_session=get_session, people_caller=people_caller
    )
    # Адрес поиска по почте не должен попасть в access log uvicorn.
    install_access_log_filter()

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    def token_issuer() -> TokenIssuer:
        return TokenIssuer(
            issuer=runtime_settings.issuer,
            private_key=runtime_settings.resolved_signing_private_key(),
            key_id=runtime_settings.signing_key_id,
            ttl_seconds=runtime_settings.token_ttl_seconds,
        )

    @app.get("/.well-known/jwks.json")
    async def jwks() -> dict[str, list[dict[str, str]]]:
        return token_issuer().jwks()

    @app.post("/api/v1/tenants", response_model=TenantView, status_code=201)
    async def create_tenant(
        body: TenantCreate,
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> Tenant:
        tenant = Tenant(slug=body.slug, name=body.name)
        if body.id is not None:
            if await session.get(Tenant, body.id) is not None:
                raise HTTPException(status_code=409, detail="tenant_id_exists")
            tenant.id = body.id
        session.add(tenant)
        await session.flush()
        session.add(
            OutboxEvent(
                tenant_id=tenant.id,
                type="tenant.created",
                aggregate_type="tenant",
                aggregate_id=tenant.id,
                payload={"tenantId": str(tenant.id), "slug": tenant.slug},
            )
        )
        session.add(
            AuditEvent(
                tenant_id=tenant.id,
                action="tenants.create",
                actor_ref=actor,
                resource_type="tenant",
                resource_id=tenant.id,
                outcome="allowed",
            )
        )
        try:
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail="tenant_slug_exists") from exc
        return tenant

    @app.get("/api/v1/events", response_model=EventPage)
    async def list_events(
        after: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=500),
        _: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> EventPage:
        rows = list(
            await session.scalars(
                select(OutboxEvent)
                .where(OutboxEvent.sequence > after)
                .order_by(OutboxEvent.sequence)
                .limit(limit + 1)
            )
        )
        has_more = len(rows) > limit
        items = rows[:limit]
        return EventPage(
            items=[EventView.model_validate(item) for item in items],
            next_after=items[-1].sequence if has_more and items else None,
        )

    async def tenant_principal(
        session: AsyncSession, tenant_id: uuid.UUID, principal_id: uuid.UUID
    ) -> Principal:
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
        return principal

    async def replayed_principal(
        session: AsyncSession, tenant_id: uuid.UUID, actor_ref: str, idempotency_key: str
    ) -> Principal | None:
        return await session.scalar(
            select(Principal)
            .join(TenantMembership, TenantMembership.principal_id == Principal.id)
            .where(
                TenantMembership.tenant_id == tenant_id,
                TenantMembership.idempotency_actor == actor_ref,
                TenantMembership.idempotency_key == idempotency_key,
            )
        )

    async def people_principal(
        session: AsyncSession,
        caller: Caller,
        *,
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        action: str,
    ) -> Principal:
        """`tenant_principal` маршрутов управления людьми: промах пишется в audit.

        Записи audit нужен существующий tenant: bootstrap может спросить и о
        несуществующем, человеку tenant уже подтвердил guard.
        """

        try:
            return await tenant_principal(session, tenant_id, principal_id)
        except HTTPException:
            if await session.get(Tenant, tenant_id) is None:
                raise
            raise await refuse(
                session,
                tenant_id=tenant_id,
                action=action,
                actor_ref=caller.actor_ref,
                resource_id=principal_id,
                status_code=404,
                detail="principal_not_found",
            ) from None

    async def require_onboarding_link(
        session: AsyncSession,
        caller: Caller,
        *,
        tenant_id: uuid.UUID,
        principal: Principal,
        issuer: str,
    ) -> None:
        """Человек со `iam:people` привязывает identity только при онбординге.

        Иначе он привязал бы к чужому Principal пару (issuer, subject), которую
        контролирует сам, и federation-вход усыновил бы её — захват аккаунта.
        Поэтому по Bearer: цель — не сам вызывающий, issuer — активный
        провайдер tenant'а, а у цели ещё нет способа входа — ни одной external
        identity, кроме identity подключений (и отключённой тоже), ни
        действующего PAT или client secret — и
        она не член группы администраторов людей. Всё прочее — только
        bootstrap.
        """

        target_id = principal.id

        async def deny(status_code: int, detail: str, reason: str = "") -> HTTPException:
            return await refuse(
                session,
                tenant_id=tenant_id,
                action="external_identities.link",
                actor_ref=caller.actor_ref,
                resource_id=target_id,
                status_code=status_code,
                detail=detail,
                reason=reason,
            )

        if target_id == caller.principal_id:
            raise await deny(403, "self_link_forbidden")
        # Блокировка цели до проверок: две параллельные привязки к одному
        # новичку иначе обе увидели бы «identity нет».
        await session.scalar(
            select(Principal.id).where(Principal.id == target_id).with_for_update()
        )
        provider = await session.scalar(
            select(IdentityProvider.id).where(
                IdentityProvider.tenant_id == tenant_id,
                IdentityProvider.issuer == issuer,
                IdentityProvider.status == "active",
            )
        )
        if provider is None:
            raise await deny(422, "identity_provider_unknown", f"issuer:{issuer}")
        # Identity подключения входа не даёт (ADR-0004, п. 3) и онбордингу не мешает.
        existing = await session.scalar(
            select(ExternalIdentity.id)
            .where(
                ExternalIdentity.principal_id == target_id,
                ExternalIdentity.source != CONNECTION_SOURCE,
            )
            .limit(1)
        )
        if existing is not None:
            raise await deny(409, "principal_has_identity", f"identity:{existing}")
        now = datetime.now(UTC)
        for credential in await session.scalars(
            select(PlatformAccessToken).where(
                PlatformAccessToken.principal_id == target_id,
                PlatformAccessToken.revoked_at.is_(None),
            )
        ):
            expires_at = credential.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            if expires_at > now:
                raise await deny(409, "principal_has_credential", f"pat:{credential.id}")
        # Недостижимо: require_human_target раньше отсекает не-людей, а service
        # account есть только у Principal своего вида. Защита оставлена
        # намеренно — на случай, если порядок проверок изменится.
        account = await session.scalar(
            select(ServiceAccount.id)
            .where(ServiceAccount.principal_id == target_id, ServiceAccount.revoked_at.is_(None))
            .limit(1)
        )
        if account is not None:
            raise await deny(409, "principal_has_credential", f"service_account:{account}")
        # Членство любого статуса в группе привилегированного scope (ADR-0003):
        # identity, привязанная к такому человеку, дала бы вызывающему второй
        # вход администратора людей или fleet.
        admin_group = await session.scalar(
            select(Group.key)
            .join(GroupMember, GroupMember.group_id == Group.id)
            .where(
                Group.tenant_id == tenant_id,
                Group.key.in_(sorted(runtime_settings.privileged_group_keys())),
                GroupMember.principal_id == target_id,
            )
            .order_by(Group.key)
            .limit(1)
        )
        if admin_group is not None:
            raise await deny(403, "people_admin_protected", f"group:{admin_group}")

    def people_reason(caller: Caller) -> str:
        if caller.bootstrap:
            return ""
        if caller.agent:
            return f"scope:{runtime_settings.identities_link_scope} pat:{caller.credential_id}"
        return f"scope:{runtime_settings.people_scope} identity:{caller.external_identity_id}"

    async def require_own_connection_issuer(
        session: AsyncSession,
        caller: Caller,
        *,
        tenant_id: uuid.UUID,
        issuer: str,
        action: str,
        resource_id: uuid.UUID,
    ) -> None:
        """Агент со `iam:identities.link` — только issuer подключений своего tenant'а.

        Identity входа (IdP, каналы), подключения чужого tenant'а и любая иная
        строка агенту не отвечают ничем, кроме отказа — до проверки формы
        issuer и цели (ADR-0004, п. 5). Tenant token совпадает с путём: это
        проверил guard.
        """

        if not caller.agent or issuer.startswith(tenant_connection_prefix(tenant_id)):
            return
        raise await refuse(
            session,
            tenant_id=tenant_id,
            action=action,
            actor_ref=caller.actor_ref,
            resource_id=resource_id,
            status_code=403,
            detail="issuer_not_allowed",
            reason=f"issuer:{issuer}",
        )

    @app.post(
        "/api/v1/tenants/{tenant_id}/principals", response_model=PrincipalView, status_code=201
    )
    async def create_principal(
        tenant_id: uuid.UUID,
        body: PrincipalCreate,
        response: Response,
        idempotency_key: str = Header(default="", alias="Idempotency-Key", max_length=200),
        caller: Caller = Depends(people_caller),
        session: AsyncSession = Depends(get_session),
    ) -> Principal:
        """Завести Principal в tenant.

        Bootstrap заводит любой вид, человек со `iam:people` — только `human` и
        только с `Idempotency-Key`: повтор после неоднозначного ответа вернёт
        того же Principal, а не заведёт второго.
        """

        if await session.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        if not caller.bootstrap:
            if body.kind != "human":
                raise await refuse(
                    session,
                    tenant_id=tenant_id,
                    action="principals.create",
                    actor_ref=caller.actor_ref,
                    resource_id=caller.principal_id,
                    status_code=422,
                    detail="human_principal_required",
                    reason=f"human_principal_required kind:{body.kind}",
                )
            if not idempotency_key:
                raise HTTPException(status_code=400, detail="idempotency_key_required")

        async def replay() -> Principal | None:
            # Ключ ищется только среди созданий того же вызывающего.
            existing = await replayed_principal(
                session, tenant_id, caller.actor_ref, idempotency_key
            )
            if existing is None:
                return None
            if existing.kind != body.kind or existing.display_name != body.display_name:
                raise await refuse(
                    session,
                    tenant_id=tenant_id,
                    action="principals.create",
                    actor_ref=caller.actor_ref,
                    resource_id=existing.id,
                    status_code=409,
                    detail="idempotency_key_reused",
                )
            response.headers["Idempotency-Replayed"] = "true"
            return existing

        if idempotency_key and (existing := await replay()) is not None:
            return existing

        principal = Principal(kind=body.kind, display_name=body.display_name)
        session.add(principal)
        await session.flush()
        session.add(
            TenantMembership(
                tenant_id=tenant_id,
                principal_id=principal.id,
                idempotency_key=idempotency_key or None,
                idempotency_actor=caller.actor_ref if idempotency_key else None,
            )
        )
        session.add(
            OutboxEvent(
                tenant_id=tenant_id,
                type="principal.created",
                aggregate_type="principal",
                aggregate_id=principal.id,
                payload={"principalId": str(principal.id), "kind": principal.kind},
            )
        )
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action="principals.create",
                actor_ref=caller.actor_ref,
                resource_type="principal",
                resource_id=principal.id,
                outcome="allowed",
                reason=people_reason(caller),
            )
        )
        try:
            await session.commit()
        except IntegrityError as exc:
            # Параллельный запрос с тем же ключом успел первым.
            await session.rollback()
            concurrent = await replay() if idempotency_key else None
            if concurrent is None:
                raise HTTPException(status_code=409, detail="principal_conflict") from exc
            return concurrent
        return principal

    @app.get("/api/v1/tenants/{tenant_id}/principals", response_model=PrincipalPage)
    async def list_principals(
        tenant_id: uuid.UUID,
        kind: str | None = Query(default=None, pattern=r"^(human|agent|service_account|workload)$"),
        after: uuid.UUID | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
        _: Caller = Depends(people_caller),
        session: AsyncSession = Depends(get_session),
    ) -> PrincipalPage:
        """Principals tenant'а постранично, по возрастанию id (курсор `after`)."""

        if await session.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        query = (
            select(Principal)
            .join(TenantMembership, TenantMembership.principal_id == Principal.id)
            .where(
                TenantMembership.tenant_id == tenant_id,
                TenantMembership.status == "active",
            )
        )
        if kind is not None:
            query = query.where(Principal.kind == kind)
        if after is not None:
            query = query.where(Principal.id > after)
        rows = list(await session.scalars(query.order_by(Principal.id).limit(limit + 1)))
        items = rows[:limit]
        return PrincipalPage(
            items=[PrincipalView.model_validate(item) for item in items],
            next_after=items[-1].id if len(rows) > limit else None,
        )

    @app.get(
        "/api/v1/tenants/{tenant_id}/principals/{principal_id}",
        response_model=PrincipalView,
    )
    async def get_principal(
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        _: Caller = Depends(people_caller),
        session: AsyncSession = Depends(get_session),
    ) -> Principal:
        return await tenant_principal(session, tenant_id, principal_id)

    @app.get(
        "/api/v1/tenants/{tenant_id}/principals:by-email",
        response_model=PrincipalByEmailPage,
        responses={422: {"description": "`invalid_email`"}},
    )
    async def find_principals_by_email(
        tenant_id: uuid.UUID,
        # Длина и форма проверяются здесь, а не валидатором FastAPI: ошибка
        # валидации повторила бы адрес в теле ответа.
        email: str = Query(json_schema_extra={"minLength": 3, "maxLength": EMAIL_MAX_LENGTH}),
        _: Caller = Depends(identities_caller),
        session: AsyncSession = Depends(get_session),
    ) -> PrincipalByEmailPage:
        """Люди tenant'а по почте, подтверждённой IdP при входе (ADR-0004, п. 2).

        Только `human` и `active` с активным membership; почту подтвердил
        активный провайдер этого tenant'а. Все совпадения отдаются как есть —
        неоднозначность решает вызывающий. Чтение в audit не пишется: запись
        с адресом положила бы персональные данные в журнал.
        """

        normalized = normalize_email(email) if 3 <= len(email) <= EMAIL_MAX_LENGTH else None
        if normalized is None:
            raise HTTPException(status_code=422, detail="invalid_email")
        if await session.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        principals = await session.scalars(
            select(Principal)
            .join(TenantMembership, TenantMembership.principal_id == Principal.id)
            .join(ExternalIdentity, ExternalIdentity.principal_id == Principal.id)
            .join(IdentityProvider, IdentityProvider.id == ExternalIdentity.identity_provider_id)
            .where(
                TenantMembership.tenant_id == tenant_id,
                TenantMembership.status == "active",
                Principal.kind == "human",
                Principal.status == "active",
                # Человек из SCIM, вошедший через IdP, остаётся `provisioned`:
                # усыновление меняет source только identity без провайдера.
                # Почту и у неё пишет только federation-вход.
                ExternalIdentity.source.in_(("federated", "provisioned")),
                ExternalIdentity.status == "active",
                ExternalIdentity.email == normalized,
                IdentityProvider.tenant_id == tenant_id,
                IdentityProvider.status == "active",
            )
            .distinct()
            .order_by(Principal.id)
        )
        return PrincipalByEmailPage(
            items=[PrincipalView.model_validate(item) for item in principals]
        )

    def identity_page(identities: list[ExternalIdentity]) -> ExternalIdentityPage:
        return ExternalIdentityPage(
            items=[ExternalIdentityItem.model_validate(item) for item in identities]
        )

    @app.get(
        "/api/v1/tenants/{tenant_id}/external-identities",
        response_model=ExternalIdentityPage,
    )
    async def find_external_identity(
        tenant_id: uuid.UUID,
        issuer: str = Query(min_length=1, max_length=500),
        subject: str | None = Query(default=None, min_length=1, max_length=500),
        after: uuid.UUID | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=200),
        caller: Caller = Depends(identities_caller),
        session: AsyncSession = Depends(get_session),
    ) -> ExternalIdentityPage:
        """External identities tenant'а по issuer: с `subject` — точная пара (0 или 1).

        Пара уникальна глобально, но видна только identity Principal с
        активным membership этого tenant'а: чужой tenant — пустой ответ, а не
        404, чтобы не отличать «нет такой» от «есть, но не у вас». Статус
        отдаётся как есть — отключённая identity тоже занимает пару. Без
        `subject` — все identity issuer'а постранично, по возрастанию `id`
        (ADR-0004, п. 4.3); агент — только issuer подключений своего tenant'а.
        """

        if await session.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        await require_own_connection_issuer(
            session,
            caller,
            tenant_id=tenant_id,
            issuer=issuer,
            action="external_identities.find",
            resource_id=caller.principal_id or tenant_id,
        )
        query = (
            select(ExternalIdentity)
            .join(TenantMembership, TenantMembership.principal_id == ExternalIdentity.principal_id)
            .where(
                TenantMembership.tenant_id == tenant_id,
                TenantMembership.status == "active",
                ExternalIdentity.issuer == issuer,
            )
        )
        if subject is not None:
            found = await session.scalars(query.where(ExternalIdentity.subject == subject).limit(1))
            return identity_page(list(found))
        if after is not None:
            query = query.where(ExternalIdentity.id > after)
        rows = list(await session.scalars(query.order_by(ExternalIdentity.id).limit(limit + 1)))
        items = rows[:limit]
        return ExternalIdentityPage(
            items=[ExternalIdentityItem.model_validate(item) for item in items],
            next_after=items[-1].id if len(rows) > limit else None,
        )

    @app.get(
        "/api/v1/tenants/{tenant_id}/principals/{principal_id}/external-identities",
        response_model=ExternalIdentityPage,
    )
    async def list_principal_external_identities(
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        _: Caller = Depends(people_caller),
        session: AsyncSession = Depends(get_session),
    ) -> ExternalIdentityPage:
        """External identities Principal tenant'а любого статуса, по времени привязки."""

        principal = await tenant_principal(session, tenant_id, principal_id)
        identities = await session.scalars(
            select(ExternalIdentity)
            .where(ExternalIdentity.principal_id == principal.id)
            .order_by(ExternalIdentity.created_at, ExternalIdentity.id)
        )
        return identity_page(list(identities))

    async def require_connection_target(
        session: AsyncSession,
        caller: Caller,
        *,
        tenant_id: uuid.UUID,
        principal: Principal,
        issuer: str,
    ) -> None:
        """Сопоставление подключения: форма issuer, tenant пути и цель (ADR-0004, п. 3–4.1).

        Правила онбординга ADR-0002, п. 6, здесь не действуют: identity
        подключения входа не даёт, и захватывать через неё нечего. Остаётся
        запрет на себя для администратора людей — иначе он получал бы в зачёт
        работу, закрытую во внешней системе чужими руками.
        """

        target_id, kind, status = principal.id, principal.kind, principal.status

        async def deny(status_code: int, detail: str, reason: str) -> HTTPException:
            return await refuse(
                session,
                tenant_id=tenant_id,
                action="external_identities.link",
                actor_ref=caller.actor_ref,
                resource_id=target_id,
                status_code=status_code,
                detail=detail,
                reason=reason,
            )

        issuer_tenant = connection_issuer_tenant(issuer)
        if issuer_tenant is None:
            raise await deny(422, "invalid_connection_issuer", f"issuer:{issuer}")
        # Tenant issuer'а — tenant пути для любого вызывающего, включая bootstrap.
        if issuer_tenant != tenant_id:
            raise await deny(422, "issuer_tenant_mismatch", f"issuer:{issuer}")
        if kind != "human":
            raise await deny(422, "human_principal_required", f"kind:{kind}")
        if caller.bootstrap:
            return
        if status != "active":
            raise await deny(409, "principal_not_active", f"status:{status}")
        if not caller.agent and target_id == caller.principal_id:
            raise await deny(403, "self_link_forbidden", "self_link_forbidden")

    @app.post(
        "/api/v1/tenants/{tenant_id}/principals/{principal_id}/external-identities",
        response_model=ExternalIdentityView,
        status_code=201,
    )
    async def link_external_identity(
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        body: ExternalIdentityCreate,
        caller: Caller = Depends(identities_caller),
        session: AsyncSession = Depends(get_session),
    ) -> ExternalIdentity:
        """Привязать identity; issuer `connection:<tenant>:<key>` — сопоставление подключения.

        Источник выводится из issuer, а не выбирается вызывающим: префикс
        `connection:` — всегда `source = connection` (ADR-0004, п. 3), иначе —
        `manual` по прежним правилам (ADR-0002, п. 6). Агент со
        `iam:identities.link` привязывает только identity подключений своего
        tenant'а.
        """

        action = "external_identities.link"
        await require_own_connection_issuer(
            session,
            caller,
            tenant_id=tenant_id,
            issuer=body.issuer,
            action=action,
            resource_id=principal_id,
        )
        principal = await people_principal(
            session, caller, tenant_id=tenant_id, principal_id=principal_id, action=action
        )
        source = CONNECTION_SOURCE if is_connection_issuer(body.issuer) else "manual"
        if source == CONNECTION_SOURCE:
            await require_connection_target(
                session, caller, tenant_id=tenant_id, principal=principal, issuer=body.issuer
            )
        else:
            await require_human_target(
                session, caller, tenant_id=tenant_id, principal=principal, action=action
            )
            if not caller.bootstrap:
                await require_onboarding_link(
                    session, caller, tenant_id=tenant_id, principal=principal, issuer=body.issuer
                )
            managed_by = await session.scalar(
                select(IdentityProvider).where(
                    IdentityProvider.tenant_id == tenant_id,
                    IdentityProvider.issuer == body.issuer,
                    IdentityProvider.status == "active",
                    IdentityProvider.lifecycle_profile == "read_only",
                )
            )
            if managed_by is not None:
                raise HTTPException(status_code=409, detail="identity_provider_managed")
        identity = ExternalIdentity(
            principal_id=principal.id,
            issuer=body.issuer,
            subject=body.subject,
            source=source,
        )
        session.add(identity)
        try:
            await session.flush()
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="external_identity.linked",
                    aggregate_type="external_identity",
                    aggregate_id=identity.id,
                    payload={
                        "externalIdentityId": str(identity.id),
                        "principalId": str(principal.id),
                        "source": source,
                        "issuer": body.issuer,
                    },
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="external_identities.link",
                    actor_ref=caller.actor_ref,
                    resource_type="external_identity",
                    resource_id=identity.id,
                    outcome="allowed",
                    reason=f"issuer:{body.issuer} {people_reason(caller)}".strip()[:1000],
                )
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail="external_identity_exists") from exc
        return identity

    @app.delete(
        "/api/v1/tenants/{tenant_id}/principals/{principal_id}/external-identities/{identity_id}",
        status_code=204,
        response_class=Response,
    )
    async def unlink_connection_identity(
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        identity_id: uuid.UUID,
        caller: Caller = Depends(identities_caller),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        """Снять сопоставление identity подключения; пара освобождается (ADR-0004, п. 4.2).

        Только `source = connection`: identity входа (IdP, SCIM, каналы)
        снимаются своими путями. Строка удаляется, а не отключается, чтобы
        пользователя внешней системы можно было сопоставить другому человеку.
        """

        action = "external_identities.unlink"
        identity = await session.get(ExternalIdentity, identity_id)
        owned = (
            identity is not None
            and identity.principal_id == principal_id
            and await session.scalar(
                select(TenantMembership.principal_id).where(
                    TenantMembership.principal_id == principal_id,
                    TenantMembership.tenant_id == tenant_id,
                    TenantMembership.status == "active",
                )
            )
            is not None
        )

        async def deny(status_code: int, detail: str, reason: str = "") -> HTTPException:
            return await refuse(
                session,
                tenant_id=tenant_id,
                action=action,
                actor_ref=caller.actor_ref,
                resource_id=principal_id,
                status_code=status_code,
                detail=detail,
                reason=reason,
            )

        # Агенту чужое пространство имён отвечает отказом раньше, чем 404 за
        # чужого Principal или tenant (ADR-0004, п. 5). Tenant агента проверил guard.
        if identity is not None:
            await require_own_connection_issuer(
                session,
                caller,
                tenant_id=tenant_id,
                issuer=identity.issuer,
                action=action,
                resource_id=principal_id,
            )
        if identity is None or not owned:
            # Записи audit нужен существующий tenant: bootstrap может спросить
            # и о несуществующем.
            if await session.get(Tenant, tenant_id) is None:
                raise HTTPException(status_code=404, detail="external_identity_not_found")
            raise await deny(404, "external_identity_not_found", f"identity:{identity_id}")
        issuer, source = identity.issuer, identity.source
        if source != CONNECTION_SOURCE:
            raise await deny(422, "connection_identity_required", f"source:{source}")
        # Tenant issuer'а — tenant пути для любого вызывающего, включая bootstrap:
        # identity чужого tenant'а могла попасть в базу только в обход API.
        if not issuer.startswith(tenant_connection_prefix(tenant_id)):
            raise await deny(422, "issuer_tenant_mismatch", f"issuer:{issuer}")
        if not caller.bootstrap and not caller.agent and principal_id == caller.principal_id:
            raise await deny(403, "self_link_forbidden")
        await session.delete(identity)
        session.add(
            OutboxEvent(
                tenant_id=tenant_id,
                type="external_identity.unlinked",
                aggregate_type="external_identity",
                aggregate_id=identity_id,
                payload={
                    "externalIdentityId": str(identity_id),
                    "principalId": str(principal_id),
                    "source": source,
                    "issuer": issuer,
                },
            )
        )
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action=action,
                actor_ref=caller.actor_ref,
                resource_type="external_identity",
                resource_id=identity_id,
                outcome="allowed",
                reason=f"issuer:{issuer} {people_reason(caller)}".strip()[:1000],
            )
        )
        await session.commit()
        return Response(status_code=204)

    @app.post(
        "/api/v1/tenants/{tenant_id}/identity-providers",
        response_model=IdentityProviderView,
        status_code=201,
    )
    async def create_identity_provider(
        tenant_id: uuid.UUID,
        body: IdentityProviderCreate,
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> IdentityProvider:
        if await session.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        if not body.issuer.startswith(("http://", "https://")):
            raise HTTPException(status_code=422, detail="invalid_issuer")
        provider = IdentityProvider(
            tenant_id=tenant_id,
            key=body.key,
            issuer=body.issuer.rstrip("/") if body.issuer.endswith("/") else body.issuer,
            audience=body.audience,
            jwks_uri=body.jwks_uri,
            subject_claim=body.subject_claim,
            external_id_claim=body.external_id_claim,
            group_claim=body.group_claim,
            group_mappings=dict(body.group_mappings),
            required_acr_values=sorted(set(body.required_acr_values)),
            required_amr_values=sorted(set(body.required_amr_values)),
            lifecycle_profile=body.lifecycle_profile,
            jwks_cache_ttl_seconds=body.jwks_cache_ttl_seconds,
            jwks_stale_grace_seconds=body.jwks_stale_grace_seconds,
        )
        session.add(provider)
        try:
            await session.flush()
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="identity_provider.registered",
                    aggregate_type="identity_provider",
                    aggregate_id=provider.id,
                    payload={
                        "identityProviderId": str(provider.id),
                        "key": provider.key,
                        "lifecycleProfile": provider.lifecycle_profile,
                    },
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="identity_providers.create",
                    actor_ref=actor,
                    resource_type="identity_provider",
                    resource_id=provider.id,
                    outcome="allowed",
                    reason=f"provider:{provider.key}",
                )
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail="identity_provider_exists") from exc
        return provider

    async def federate(
        session: AsyncSession,
        *,
        tenant_id: uuid.UUID,
        identity_provider: str,
        token: str,
        action: str,
    ) -> FederationOutcome:
        """Общая часть `federation:authenticate` и `federation:exchange`.

        Проверка upstream token, linking, проекция групп и снимок
        authentication context — одна и та же дорога независимо от того,
        нужен ли клиенту после входа credential. Отказ уже записан в audit
        под `action` и закоммичен; вызывающему остаётся положительная запись.
        """

        provider = await session.scalar(
            select(IdentityProvider).where(
                IdentityProvider.tenant_id == tenant_id,
                IdentityProvider.key == identity_provider,
                IdentityProvider.status == "active",
            )
        )
        if provider is None:
            raise HTTPException(status_code=404, detail="identity_provider_not_found")
        # После rollback ORM-объект провайдера недоступен, а audit его ещё ждёт.
        provider_id, provider_key = provider.id, provider.key
        try:
            resolved = await jwks_resolver.resolve(
                provider_id=provider.id,
                issuer=provider.issuer,
                jwks_uri=provider.jwks_uri,
                cache_ttl_seconds=provider.jwks_cache_ttl_seconds,
                stale_grace_seconds=provider.jwks_stale_grace_seconds,
            )
            claims = verify_upstream_token(
                token,
                keys=resolved.keys,
                issuer=provider.issuer,
                audience=provider.audience,
            )
            upstream = read_claims(
                claims,
                subject_claim=provider.subject_claim,
                external_id_claim=provider.external_id_claim,
                group_claim=provider.group_claim,
            )
            ensure_authentication_context(
                upstream.context,
                required_acr_values=provider.required_acr_values,
                required_amr_values=provider.required_amr_values,
            )
            linked = await link_identity(
                session, tenant_id=tenant_id, provider=provider, upstream=upstream
            )
            groups = await reconcile_group_projection(
                session,
                tenant_id=tenant_id,
                provider=provider,
                principal_id=linked.principal.id,
                group_keys=project_groups(upstream.groups, mappings=provider.group_mappings),
                reserved_keys=runtime_settings.privileged_group_keys(),
            )
        except (FederationError, IntegrityError) as exc:
            await session.rollback()
            code = exc.code if isinstance(exc, FederationError) else "external_identity_conflict"
            status_code = exc.status_code if isinstance(exc, FederationError) else 409
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action=action,
                    actor_ref=f"provider:{provider_key}",
                    resource_type="identity_provider",
                    resource_id=provider_id,
                    outcome="denied",
                    reason=code,
                )
            )
            await session.commit()
            raise HTTPException(status_code=status_code, detail=code) from exc

        touch_authentication(linked.identity, acr=upstream.context.acr)
        # Подтверждённый вход открывает человеку выпуск Platform Access Token:
        # снимок пишется в той же транзакции, что и linking.
        context = record_authentication_context(
            session,
            tenant_id=tenant_id,
            principal_id=linked.principal.id,
            issuer=provider.issuer,
            acr=upstream.context.acr,
            amr=list(upstream.context.amr),
            auth_time=upstream.context.auth_time,
            external_identity_id=linked.identity.id,
        )
        return FederationOutcome(
            provider=provider,
            resolved=resolved,
            upstream=upstream,
            linked=linked,
            groups=groups,
            context=context,
        )

    @app.post(
        "/api/v1/tenants/{tenant_id}/federation:authenticate",
        response_model=FederatedIdentityView,
    )
    async def authenticate_federated_identity(
        tenant_id: uuid.UUID,
        body: FederationAuthenticateRequest,
        session: AsyncSession = Depends(get_session),
    ) -> FederatedIdentityView:
        outcome = await federate(
            session,
            tenant_id=tenant_id,
            identity_provider=body.identity_provider,
            token=body.token,
            action="federation.authenticate",
        )
        acr = outcome.upstream.context.acr or "none"
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action="federation.authenticate",
                actor_ref=str(outcome.linked.principal.id),
                resource_type="external_identity",
                resource_id=outcome.linked.identity.id,
                outcome="allowed",
                reason=f"provider:{outcome.provider.key} acr:{acr}"
                + (" jwks:stale" if outcome.resolved.stale else ""),
            )
        )
        await session.commit()
        return FederatedIdentityView(
            principalId=outcome.linked.principal.id,
            identityProvider=outcome.provider.key,
            groups=outcome.groups,
            authenticationContext=outcome.authentication_context(),
            identityProviderStale=outcome.resolved.stale,
        )

    @app.post(
        "/api/v1/tenants/{tenant_id}/federation:exchange",
        response_model=FederationExchangeResponse,
    )
    async def exchange_federated_identity(
        tenant_id: uuid.UUID,
        body: FederationExchangeRequest,
        session: AsyncSession = Depends(get_session),
    ) -> FederationExchangeResponse:
        """Вход через upstream IdP и сразу credential одного audience.

        Для человека в браузере: у шлюза есть только его upstream token, а
        Platform Access Token существует для локального harness и через
        веб-сессию не проходит. Токен выпускается той же формы, что при обмене
        PAT, — resource service отличий не видит. Потолок здесь — allowlist
        audience: собственного ceiling у веб-входа нет.
        """

        outcome = await federate(
            session,
            tenant_id=tenant_id,
            identity_provider=body.identity_provider,
            token=body.token,
            action="federation.exchange",
        )
        principal, identity = outcome.linked.principal, outcome.linked.identity
        provider_key = outcome.provider.key

        async def deny(status_code: int, detail: str, reason: str = "") -> HTTPException:
            # Вход состоялся и остаётся в базе: отказ относится к выпуску
            # credential, а не к identity, и audit должен показывать оба факта.
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="federation.exchange",
                    actor_ref=str(principal.id),
                    resource_type="external_identity",
                    resource_id=identity.id,
                    outcome="denied",
                    reason=f"provider:{provider_key} audience:{body.audience} {detail}"
                    + (f" {reason}" if reason else ""),
                )
            )
            await session.commit()
            return HTTPException(status_code=status_code, detail=detail)

        # Federation заводит только human Principal; сюда иной вид попадёт
        # разве что через ручную привязку identity к service account — и это
        # не дорога для client credentials.
        if principal.kind != "human":
            raise await deny(422, "human_principal_required")
        audience = await session.scalar(
            select(Audience).where(
                Audience.tenant_id == tenant_id,
                Audience.key == body.audience,
                Audience.status == "active",
            )
        )
        if audience is None:
            raise await deny(403, "audience_not_allowed")
        allowed = set(audience.allowed_scopes)
        requested = set(body.scopes)
        if not requested.issubset(allowed):
            raise await deny(403, "scope_not_allowed")
        # Привилегированные scope (`iam:people`, `fleet:admin`, ADR-0003) —
        # ограничение конкретного человека поверх audience: только член
        # группы из реестра (проекция групп выше уже привела членства к token
        # IdP) и только по явному запросу.
        privileged = runtime_settings.privileged_scope_groups()
        entitled = await entitled_privileged_scopes(
            session,
            tenant_id=tenant_id,
            principal_id=principal.id,
            scopes=allowed,
            privileged=privileged,
        )
        withheld = {scope for scope in allowed if scope in privileged} - entitled
        refused = sorted(requested & withheld)
        if refused:
            raise await deny(
                403,
                "scope_not_allowed",
                " ".join(f"group:{privileged[scope]}" for scope in refused),
            )
        ceiling = allowed - withheld
        # Пустой запрос означает «всё, что разрешено audience», кроме
        # привилегированных scope: их выдаёт только явный запрос.
        effective = sorted(requested or allowed - privileged.keys())
        granted = [scope for scope in effective if scope in privileged]

        session_id = uuid.uuid4()
        token = token_issuer().issue(
            subject=principal.id,
            tenant_id=tenant_id,
            audience=body.audience,
            scopes=effective,
            # Credential здесь — сама external identity: её отзыв (disable)
            # закрывает и следующий обмен, а resource service получает
            # стабильный ключ для своего revocation-кэша.
            credential_id=identity.id,
            principal_type=principal.kind,
            scope_ceiling=sorted(ceiling),
            session_id=session_id,
            # Тот же формат, что в снимке PAT: ISO 8601, серверная подрезка
            # будущего `auth_time` уже применена в record_authentication_context.
            auth_time=outcome.context.auth_time.isoformat(),
            acr=outcome.context.acr,
        )
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action="federation.exchange",
                actor_ref=str(principal.id),
                resource_type="external_identity",
                resource_id=identity.id,
                outcome="allowed",
                reason=f"provider:{provider_key} audience:{body.audience} session:{session_id}"
                + "".join(f" privileged:{scope}@group:{privileged[scope]}" for scope in granted)
                + (" jwks:stale" if outcome.resolved.stale else ""),
            )
        )
        await session.commit()
        return FederationExchangeResponse(
            accessToken=token,
            expiresIn=runtime_settings.token_ttl_seconds,
            audience=body.audience,
            scope=effective,
            sessionId=session_id,
            principalId=principal.id,
            identityProvider=provider_key,
            groups=outcome.groups,
            authenticationContext=outcome.authentication_context(),
            identityProviderStale=outcome.resolved.stale,
        )

    @app.post("/api/v1/tenants/{tenant_id}/audiences", response_model=AudienceView, status_code=201)
    async def create_audience(
        tenant_id: uuid.UUID,
        body: AudienceCreate,
        _: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> Audience:
        if await session.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        allowed_scopes = sorted(set(body.allowed_scopes))
        if any(not scope or len(scope) > 120 for scope in allowed_scopes):
            raise HTTPException(status_code=422, detail="invalid_scope")
        audience = Audience(
            tenant_id=tenant_id,
            key=body.key,
            allowed_scopes=allowed_scopes,
        )
        session.add(audience)
        try:
            await session.flush()
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="audience.created",
                    aggregate_type="audience",
                    aggregate_id=audience.id,
                    payload={"audienceId": str(audience.id), "key": audience.key},
                )
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail="audience_exists") from exc
        return audience

    @app.get("/api/v1/tenants/{tenant_id}/audiences", response_model=list[AudienceView])
    async def list_audiences(
        tenant_id: uuid.UUID,
        _: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> list[Audience]:
        if await session.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        rows = await session.scalars(
            select(Audience).where(Audience.tenant_id == tenant_id).order_by(Audience.key)
        )
        return list(rows)

    @app.patch("/api/v1/tenants/{tenant_id}/audiences/{key}", response_model=AudienceView)
    async def update_audience(
        tenant_id: uuid.UUID,
        key: str,
        body: AudienceUpdate,
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> Audience:
        """Заменить allowed scopes audience целиком (идемпотентно).

        Потолок scope сервиса растёт вместе с сервисом (например, ``memory:tenants``
        у memory-service); без этой операции уже заведённый audience можно было бы
        расширить только SQL.
        """
        audience = await session.scalar(
            select(Audience).where(Audience.tenant_id == tenant_id, Audience.key == key)
        )
        if audience is None:
            raise HTTPException(status_code=404, detail="audience_not_found")
        allowed_scopes = sorted(set(body.allowed_scopes))
        if any(not scope or len(scope) > 120 for scope in allowed_scopes):
            raise HTTPException(status_code=422, detail="invalid_scope")
        if allowed_scopes != list(audience.allowed_scopes):
            audience.allowed_scopes = allowed_scopes
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="audience.updated",
                    aggregate_type="audience",
                    aggregate_id=audience.id,
                    payload={
                        "audienceId": str(audience.id),
                        "key": audience.key,
                        "allowedScopes": allowed_scopes,
                    },
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="audiences.update",
                    actor_ref=actor,
                    resource_type="audience",
                    resource_id=audience.id,
                    outcome="allowed",
                )
            )
            await session.commit()
            await session.refresh(audience)
        return audience

    @app.post("/api/v1/tenants/{tenant_id}/groups", response_model=GroupView, status_code=201)
    async def create_group(
        tenant_id: uuid.UUID,
        body: GroupCreate,
        _: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> Group:
        if await session.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        group = Group(tenant_id=tenant_id, key=body.key, name=body.name)
        session.add(group)
        try:
            await session.flush()
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="group.created",
                    aggregate_type="group",
                    aggregate_id=group.id,
                    payload={"groupId": str(group.id), "key": group.key},
                )
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail="group_exists") from exc
        return group

    @app.post(
        "/api/v1/tenants/{tenant_id}/groups/{group_id}/members",
        response_model=GroupMemberView,
        status_code=201,
    )
    async def add_group_member(
        tenant_id: uuid.UUID,
        group_id: uuid.UUID,
        body: GroupMemberCreate,
        _: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> GroupMember:
        group = await session.scalar(
            select(Group).where(Group.id == group_id, Group.tenant_id == tenant_id)
        )
        if group is None:
            raise HTTPException(status_code=404, detail="group_not_found")
        if group.source != "local":
            # Состав federated и provisioned групп задаёт upstream: ручное
            # членство в них разошлось бы с authoritative source.
            raise HTTPException(status_code=409, detail="group_is_federated")
        await tenant_principal(session, tenant_id, body.principal_id)
        member = GroupMember(
            tenant_id=tenant_id,
            group_id=group.id,
            principal_id=body.principal_id,
        )
        session.add(member)
        try:
            await session.flush()
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="group_membership.added",
                    aggregate_type="group",
                    aggregate_id=group.id,
                    payload={
                        "groupId": str(group.id),
                        "principalId": str(body.principal_id),
                    },
                )
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail="group_membership_exists") from exc
        return member

    @app.post(
        "/api/v1/tenants/{tenant_id}/service-accounts",
        response_model=ServiceAccountIssued,
        status_code=201,
    )
    async def create_service_account(
        tenant_id: uuid.UUID,
        body: ServiceAccountCreate,
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> ServiceAccountIssued:
        known_audiences = set(
            await session.scalars(
                select(Audience.key).where(
                    Audience.tenant_id == tenant_id,
                    Audience.status == "active",
                    Audience.key.in_(body.audiences),
                )
            )
        )
        if known_audiences != set(body.audiences):
            raise HTTPException(status_code=422, detail="unknown_audience")
        principal = Principal(kind="service_account", display_name=body.display_name)
        session.add(principal)
        await session.flush()
        session.add(TenantMembership(tenant_id=tenant_id, principal_id=principal.id))
        secret = secrets.token_urlsafe(32)
        account = ServiceAccount(
            tenant_id=tenant_id,
            principal_id=principal.id,
            client_id=f"iam_sa_{secrets.token_urlsafe(18)}",
            secret_hash=password_hasher.hash(secret),
            audiences=sorted(set(body.audiences)),
            scope_ceiling=sorted(set(body.scope_ceiling)),
        )
        session.add(account)
        await session.flush()
        session.add(
            OutboxEvent(
                tenant_id=tenant_id,
                type="service_account.created",
                aggregate_type="service_account",
                aggregate_id=account.id,
                payload={
                    "serviceAccountId": str(account.id),
                    "principalId": str(principal.id),
                    "audiences": account.audiences,
                },
            )
        )
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action="service_accounts.create",
                actor_ref=actor,
                resource_type="service_account",
                resource_id=account.id,
                outcome="allowed",
            )
        )
        await session.commit()
        return ServiceAccountIssued(
            principalId=principal.id,
            clientId=account.client_id,
            clientSecret=secret,
        )

    @app.post("/api/v1/tokens/exchange", response_model=TokenResponse)
    async def exchange_token(
        body: TokenExchangeRequest,
        session: AsyncSession = Depends(get_session),
    ) -> TokenResponse:
        account = await session.scalar(
            select(ServiceAccount).where(ServiceAccount.client_id == body.client_id)
        )
        if account is None or account.revoked_at is not None:
            raise HTTPException(status_code=401, detail="invalid_client")
        try:
            password_hasher.verify(account.secret_hash, body.client_secret)
        except VerifyMismatchError as exc:
            raise HTTPException(status_code=401, detail="invalid_client") from exc
        membership = await session.get(
            TenantMembership,
            {"tenant_id": account.tenant_id, "principal_id": account.principal_id},
        )
        principal = await session.get(Principal, account.principal_id)
        if (
            membership is None
            or membership.status != "active"
            or principal is None
            or principal.status != "active"
        ):
            raise HTTPException(status_code=401, detail="invalid_client")
        if body.audience not in account.audiences:
            raise HTTPException(status_code=403, detail="audience_not_allowed")
        audience = await session.scalar(
            select(Audience).where(
                Audience.tenant_id == account.tenant_id,
                Audience.key == body.audience,
                Audience.status == "active",
            )
        )
        if audience is None:
            raise HTTPException(status_code=403, detail="audience_not_allowed")
        requested_scopes = set(body.scopes)
        if not requested_scopes.issubset(account.scope_ceiling) or not requested_scopes.issubset(
            audience.allowed_scopes
        ):
            raise HTTPException(status_code=403, detail="scope_not_allowed")
        # `iam:people` — scope человека из federation-входа; service account
        # его не получает, даже если bootstrap вписал его в потолок.
        if runtime_settings.people_scope in requested_scopes:
            raise HTTPException(status_code=403, detail="scope_not_allowed")
        token = token_issuer().issue(
            subject=account.principal_id,
            tenant_id=account.tenant_id,
            audience=body.audience,
            scopes=sorted(requested_scopes),
            credential_id=account.id,
        )
        account.last_used_at = datetime.now(UTC)
        session.add(
            AuditEvent(
                tenant_id=account.tenant_id,
                action="tokens.exchange",
                actor_ref=str(account.principal_id),
                resource_type="service_account",
                resource_id=account.id,
                outcome="allowed",
                reason=f"audience:{body.audience}",
            )
        )
        await session.commit()
        return TokenResponse(accessToken=token, expiresIn=runtime_settings.token_ttl_seconds)

    @app.patch(
        "/api/v1/tenants/{tenant_id}/service-accounts/{client_id}",
        response_model=ServiceAccountView,
    )
    async def update_service_account(
        tenant_id: uuid.UUID,
        client_id: str,
        body: ServiceAccountUpdate,
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> ServiceAccountView:
        """Изменить audiences и потолок scope service account (ADR-0005).

        Principal сохраняется, поэтому агенты, которыми он владеет (ADR-0001),
        остаются его агентами: расширение потолка не требует нового service
        account. Без изменений и без `rotateSecret` операция ничего не пишет.
        """
        account = await session.scalar(
            select(ServiceAccount).where(
                ServiceAccount.tenant_id == tenant_id,
                ServiceAccount.client_id == client_id,
            )
        )
        if account is None:
            raise HTTPException(status_code=404, detail="service_account_not_found")
        if account.revoked_at is not None:
            raise HTTPException(status_code=409, detail="service_account_revoked")
        audiences = sorted(set(account.audiences if body.audiences is None else body.audiences))
        scope_ceiling = sorted(
            set(account.scope_ceiling if body.scope_ceiling is None else body.scope_ceiling)
        )
        registered = {
            audience.key: set(audience.allowed_scopes)
            for audience in await session.scalars(
                select(Audience).where(
                    Audience.tenant_id == tenant_id,
                    Audience.status == "active",
                    Audience.key.in_(audiences),
                )
            )
        }
        if set(registered) != set(audiences):
            raise HTTPException(status_code=422, detail="unknown_audience")
        # Потолок — в пределах реестра audience: scope, которого не разрешает ни
        # один audience service account, выдать всё равно нельзя, и в потолке он
        # только скрывал бы ошибку развёртывания.
        allowed = set().union(*registered.values())
        if any(scope not in allowed for scope in scope_ceiling):
            raise HTTPException(status_code=422, detail="invalid_scope_ceiling")
        secret: str | None = None
        changed = audiences != list(account.audiences) or scope_ceiling != list(
            account.scope_ceiling
        )
        if changed:
            before_audiences = set(account.audiences)
            before_scopes = set(account.scope_ceiling)
            account.audiences = audiences
            account.scope_ceiling = scope_ceiling
            diff = [f"audience:+{key}" for key in sorted(set(audiences) - before_audiences)]
            diff += [f"audience:-{key}" for key in sorted(before_audiences - set(audiences))]
            diff += [f"scope:+{scope}" for scope in sorted(set(scope_ceiling) - before_scopes)]
            diff += [f"scope:-{scope}" for scope in sorted(before_scopes - set(scope_ceiling))]
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="service_account.updated",
                    aggregate_type="service_account",
                    aggregate_id=account.id,
                    payload={
                        "serviceAccountId": str(account.id),
                        "principalId": str(account.principal_id),
                        "audiences": audiences,
                        "scopeCeiling": scope_ceiling,
                    },
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="service_accounts.update",
                    actor_ref=actor,
                    resource_type="service_account",
                    resource_id=account.id,
                    outcome="allowed",
                    reason=",".join(diff)[:1000],
                )
            )
        if body.rotate_secret:
            # Старый секрет перестаёт работать с этим commit; уже выданные по
            # нему access token живут до своего TTL.
            secret = secrets.token_urlsafe(32)
            account.secret_hash = password_hasher.hash(secret)
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="service_account.secret_rotated",
                    aggregate_type="service_account",
                    aggregate_id=account.id,
                    payload={
                        "serviceAccountId": str(account.id),
                        "principalId": str(account.principal_id),
                    },
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="service_accounts.rotate_secret",
                    actor_ref=actor,
                    resource_type="service_account",
                    resource_id=account.id,
                    outcome="allowed",
                )
            )
        if changed or body.rotate_secret:
            await session.commit()
        return ServiceAccountView(
            principalId=account.principal_id,
            clientId=account.client_id,
            audiences=audiences,
            scopeCeiling=scope_ceiling,
            clientSecret=secret,
        )

    @app.post(
        "/api/v1/tenants/{tenant_id}/service-accounts/{client_id}:revoke",
        status_code=204,
    )
    async def revoke_service_account(
        tenant_id: uuid.UUID,
        client_id: str,
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        account = await session.scalar(
            select(ServiceAccount).where(
                ServiceAccount.tenant_id == tenant_id,
                ServiceAccount.client_id == client_id,
            )
        )
        if account is None:
            raise HTTPException(status_code=404, detail="service_account_not_found")
        if account.revoked_at is None:
            account.revoked_at = datetime.now(UTC)
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="credential.revoked",
                    aggregate_type="service_account",
                    aggregate_id=account.id,
                    payload={
                        "serviceAccountId": str(account.id),
                        "principalId": str(account.principal_id),
                    },
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="service_accounts.revoke",
                    actor_ref=actor,
                    resource_type="service_account",
                    resource_id=account.id,
                    outcome="allowed",
                )
            )
            await session.commit()
        return Response(status_code=204)

    # Platform Access Token живёт в отдельном пакете и подключается целиком.
    app.include_router(
        create_platform_token_router(
            settings=runtime_settings,
            get_session=get_session,
            require_bootstrap=require_bootstrap,
            people_caller=people_caller,
        )
    )
    # SCIM 2.0 provisioning — тоже отдельный пакет со своим форматом ошибок.
    app.include_router(
        create_scim_router(
            settings=runtime_settings,
            get_session=get_session,
            require_bootstrap=require_bootstrap,
            upstream_transport=upstream_transport,
        )
    )
    # Канал как способ входа человека (Telegram) — отдельный пакет.
    app.include_router(
        create_channel_router(
            settings=runtime_settings,
            get_session=get_session,
            require_bootstrap=require_bootstrap,
        )
    )
    # Агенты service account'а со scope `iam:agents` — без bootstrap-токена.
    app.include_router(create_agent_router(settings=runtime_settings, get_session=get_session))
    return app


app = create_app()
