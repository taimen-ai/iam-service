from __future__ import annotations

import hmac
import secrets
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from iam_service.config import Settings
from iam_service.db import Database
from iam_service.federation import (
    FederationError,
    JsonFetcher,
    JwksResolver,
    ensure_authentication_context,
    project_groups,
    read_claims,
    verify_upstream_token,
)
from iam_service.federation.linking import (
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
from iam_service.schemas import (
    AudienceCreate,
    AudienceView,
    EventPage,
    EventView,
    ExternalIdentityCreate,
    ExternalIdentityView,
    FederatedIdentityView,
    FederationAuthenticateRequest,
    FederationAuthenticationContext,
    GroupCreate,
    GroupMemberCreate,
    GroupMemberView,
    GroupView,
    IdentityProviderCreate,
    IdentityProviderView,
    PrincipalCreate,
    PrincipalView,
    ServiceAccountCreate,
    ServiceAccountIssued,
    TenantCreate,
    TenantView,
    TokenExchangeRequest,
    TokenResponse,
)
from iam_service.tokens import TokenIssuer


def create_app(
    settings: Settings | None = None, *, jwks_fetcher: JsonFetcher | None = None
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

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/jwks.json")
    async def jwks() -> dict[str, list[dict[str, str]]]:
        return TokenIssuer(
            issuer=runtime_settings.issuer,
            private_key=runtime_settings.resolved_signing_private_key(),
            key_id=runtime_settings.signing_key_id,
            ttl_seconds=runtime_settings.token_ttl_seconds,
        ).jwks()

    @app.post("/api/v1/tenants", response_model=TenantView, status_code=201)
    async def create_tenant(
        body: TenantCreate,
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> Tenant:
        tenant = Tenant(slug=body.slug, name=body.name)
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

    @app.post(
        "/api/v1/tenants/{tenant_id}/principals", response_model=PrincipalView, status_code=201
    )
    async def create_principal(
        tenant_id: uuid.UUID,
        body: PrincipalCreate,
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> Principal:
        if await session.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        principal = Principal(kind=body.kind, display_name=body.display_name)
        session.add(principal)
        await session.flush()
        session.add(TenantMembership(tenant_id=tenant_id, principal_id=principal.id))
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
                actor_ref=actor,
                resource_type="principal",
                resource_id=principal.id,
                outcome="allowed",
            )
        )
        await session.commit()
        return principal

    @app.get(
        "/api/v1/tenants/{tenant_id}/principals/{principal_id}",
        response_model=PrincipalView,
    )
    async def get_principal(
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        _: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> Principal:
        return await tenant_principal(session, tenant_id, principal_id)

    @app.post(
        "/api/v1/tenants/{tenant_id}/principals/{principal_id}/external-identities",
        response_model=ExternalIdentityView,
        status_code=201,
    )
    async def link_external_identity(
        tenant_id: uuid.UUID,
        principal_id: uuid.UUID,
        body: ExternalIdentityCreate,
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> ExternalIdentity:
        principal = await tenant_principal(session, tenant_id, principal_id)
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
                    },
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="external_identities.link",
                    actor_ref=actor,
                    resource_type="external_identity",
                    resource_id=identity.id,
                    outcome="allowed",
                )
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail="external_identity_exists") from exc
        return identity

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

    @app.post(
        "/api/v1/tenants/{tenant_id}/federation:authenticate",
        response_model=FederatedIdentityView,
    )
    async def authenticate_federated_identity(
        tenant_id: uuid.UUID,
        body: FederationAuthenticateRequest,
        session: AsyncSession = Depends(get_session),
    ) -> FederatedIdentityView:
        provider = await session.scalar(
            select(IdentityProvider).where(
                IdentityProvider.tenant_id == tenant_id,
                IdentityProvider.key == body.identity_provider,
                IdentityProvider.status == "active",
            )
        )
        if provider is None:
            raise HTTPException(status_code=404, detail="identity_provider_not_found")
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
                body.token,
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
            )
        except (FederationError, IntegrityError) as exc:
            await session.rollback()
            code = exc.code if isinstance(exc, FederationError) else "external_identity_conflict"
            status_code = exc.status_code if isinstance(exc, FederationError) else 409
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="federation.authenticate",
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
        record_authentication_context(
            session,
            tenant_id=tenant_id,
            principal_id=linked.principal.id,
            issuer=provider.issuer,
            acr=upstream.context.acr,
            amr=list(upstream.context.amr),
            auth_time=upstream.context.auth_time,
            external_identity_id=linked.identity.id,
        )
        session.add(
            AuditEvent(
                tenant_id=tenant_id,
                action="federation.authenticate",
                actor_ref=str(linked.principal.id),
                resource_type="external_identity",
                resource_id=linked.identity.id,
                outcome="allowed",
                reason=f"provider:{provider.key} acr:{upstream.context.acr or 'none'}"
                + (" jwks:stale" if resolved.stale else ""),
            )
        )
        await session.commit()
        return FederatedIdentityView(
            principalId=linked.principal.id,
            identityProvider=provider.key,
            groups=groups,
            authenticationContext=FederationAuthenticationContext(
                acr=upstream.context.acr,
                amr=list(upstream.context.amr),
                authTime=upstream.context.auth_time,
            ),
            identityProviderStale=resolved.stale,
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
        if group.source == "federated":
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
        issuer = TokenIssuer(
            issuer=runtime_settings.issuer,
            private_key=runtime_settings.resolved_signing_private_key(),
            key_id=runtime_settings.signing_key_id,
            ttl_seconds=runtime_settings.token_ttl_seconds,
        )
        token = issuer.issue(
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
        )
    )
    return app


app = create_app()
