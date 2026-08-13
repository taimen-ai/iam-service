"""SCIM 2.0 endpoints и bootstrap-управление provisioning sources.

Роутер собирается фабрикой и получает зависимости приложения снаружи, поэтому
`iam_service.app` подключает его одной строкой.

SCIM-клиент предъявляет audience-bound access token своей confidential service
identity. Человеческий credential здесь не принимается: SCIM управляет чужим
lifecycle и не является способом входа (ADR-0012).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from iam_service.config import Settings
from iam_service.models import AuditEvent, IdentityProvider, OutboxEvent, Principal, Tenant
from iam_service.scim.driver import UpstreamTransport, build_driver
from iam_service.scim.errors import SCIM_CONTENT_TYPE, ScimFault, ScimRoute
from iam_service.scim.filters import parse_filter
from iam_service.scim.models import KIND_LDAP, KIND_SCIM, ProvisioningSource, ScimGroup, ScimUser
from iam_service.scim.provisioning import (
    GROUP_FILTER_ATTRIBUTES,
    USER_FILTER_ATTRIBUTES,
    ProvisioningService,
)
from iam_service.scim.schemas import (
    ScimGroupRequest,
    ScimPatchRequest,
    ScimUserRequest,
    etag,
    group_representation,
    list_response,
    resource_types,
    schemas_document,
    service_provider_config,
    user_representation,
)
from iam_service.scim.sources import (
    ProvisioningSourceCreate,
    ProvisioningSourceView,
    source_view,
)
from iam_service.tokens import TokenIssuer, verify_access_token


def _now() -> datetime:
    return datetime.now(UTC)


def _scim(payload: dict[str, Any], *, status_code: int = 200, version: int | None = None):
    headers = {"ETag": etag(version)} if version is not None else None
    return JSONResponse(
        payload, status_code=status_code, media_type=SCIM_CONTENT_TYPE, headers=headers
    )


def create_scim_router(
    *,
    settings: Settings,
    get_session: Callable[..., Any],
    require_bootstrap: Callable[..., Any],
    upstream_transport: UpstreamTransport | None = None,
) -> APIRouter:
    router = APIRouter(route_class=ScimRoute)

    def public_key() -> Any:
        issuer = TokenIssuer(
            issuer=settings.issuer,
            private_key=settings.resolved_signing_private_key(),
            key_id=settings.signing_key_id,
            ttl_seconds=settings.token_ttl_seconds,
        )
        return issuer.private_key.public_key()

    async def provisioning(
        request: Request, session: AsyncSession = Depends(get_session)
    ) -> ProvisioningService:
        """Аутентифицировать SCIM-клиента и собрать сервис его source."""

        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise ScimFault(401, "bearer token is required")
        try:
            claims = verify_access_token(
                token,
                public_key=public_key(),
                issuer=settings.issuer,
                audience=settings.scim_audience,
            )
        except Exception as exc:
            raise ScimFault(401, "token is not valid for the SCIM audience") from exc
        if claims.get("principal_type") != "service_account":
            # Провижининг чужого lifecycle не выполняется от имени человека.
            raise ScimFault(403, "SCIM requires a confidential service identity")
        if settings.scim_scope not in set(claims.get("scope") or []):
            raise ScimFault(403, f"scope {settings.scim_scope} is required")

        source = await session.scalar(
            select(ProvisioningSource).where(
                ProvisioningSource.tenant_id == uuid.UUID(claims["tenant_id"]),
                ProvisioningSource.service_principal_id == uuid.UUID(claims["sub"]),
                ProvisioningSource.kind == KIND_SCIM,
                ProvisioningSource.status == "active",
            )
        )
        if source is None:
            raise ScimFault(403, "no active SCIM provisioning source for this identity")
        provider = await session.get(IdentityProvider, source.identity_provider_id)
        if provider is None or provider.status != "active":
            raise ScimFault(503, "identity population is unavailable")
        return ProvisioningService(
            session,
            source=source,
            provider=provider,
            driver=build_driver(source, upstream_transport),
        )

    def page(start_index: int, count: int) -> tuple[int, int]:
        return max(start_index, 1), min(max(count, 0), settings.scim_max_page_size)

    # --- управление источниками (bootstrap) -----------------------------

    @router.post(
        "/api/v1/tenants/{tenant_id}/provisioning-sources",
        response_model=ProvisioningSourceView,
        status_code=201,
        tags=["scim"],
    )
    async def register_provisioning_source(
        tenant_id: uuid.UUID,
        body: ProvisioningSourceCreate,
        actor: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> ProvisioningSourceView:
        """Объявить authoritative source одной population.

        Population — это upstream identity provider. Уникальность пары
        `(tenant, provider)` не даёт SCIM и LDAP писать в одну population, а
        `read_only` профиль провайдера прямо означает, что его lifecycle ведёт
        каталог, и SCIM-источник для него не регистрируется.
        """

        if await session.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=404, detail="tenant_not_found")
        provider = await session.scalar(
            select(IdentityProvider).where(
                IdentityProvider.tenant_id == tenant_id,
                IdentityProvider.key == body.identity_provider,
            )
        )
        if provider is None:
            raise HTTPException(status_code=404, detail="identity_provider_not_found")
        if body.kind == KIND_SCIM and provider.lifecycle_profile == "read_only":
            raise HTTPException(status_code=409, detail="population_managed_by_directory")

        service_principal_id: uuid.UUID | None = None
        if body.service_principal_id is not None:
            principal = await session.get(Principal, body.service_principal_id)
            if principal is None:
                raise HTTPException(status_code=404, detail="principal_not_found")
            if principal.kind != "service_account":
                raise HTTPException(status_code=422, detail="service_account_required")
            service_principal_id = principal.id
        if body.kind == KIND_SCIM and service_principal_id is None:
            raise HTTPException(status_code=422, detail="service_principal_required")

        source = ProvisioningSource(
            tenant_id=tenant_id,
            key=body.key,
            kind=body.kind,
            identity_provider_id=provider.id,
            service_principal_id=service_principal_id,
            upstream_mode=body.upstream_mode,
            upstream_base_url=body.upstream_base_url,
            upstream_realm=body.upstream_realm,
            stale_after_seconds=body.stale_after_seconds,
        )
        session.add(source)
        try:
            await session.flush()
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="provisioning_source.registered",
                    aggregate_type="provisioning_source",
                    aggregate_id=source.id,
                    payload={
                        "provisioningSourceId": str(source.id),
                        "key": source.key,
                        "kind": source.kind,
                        "identityProviderId": str(provider.id),
                    },
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="provisioning_sources.register",
                    actor_ref=actor,
                    resource_type="provisioning_source",
                    resource_id=source.id,
                    outcome="allowed",
                    reason=f"source:{source.key} kind:{source.kind}",
                )
            )
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(status_code=409, detail="provisioning_source_exists") from exc
        return source_view(source, now=_now())

    @router.get(
        "/api/v1/tenants/{tenant_id}/provisioning-sources",
        response_model=list[ProvisioningSourceView],
        tags=["scim"],
    )
    async def list_provisioning_sources(
        tenant_id: uuid.UUID,
        _: str = Depends(require_bootstrap),
        session: AsyncSession = Depends(get_session),
    ) -> list[ProvisioningSourceView]:
        """Состояние источников, включая устаревание.

        Молчащий authoritative source означает, что кадровые изменения
        перестали доезжать, поэтому первое обнаружение публикует событие —
        по нему строится внешний alert, а повторные чтения его не дублируют.
        """

        now = _now()
        sources = list(
            await session.scalars(
                select(ProvisioningSource)
                .where(ProvisioningSource.tenant_id == tenant_id)
                .order_by(ProvisioningSource.created_at)
            )
        )
        views = [source_view(source, now=now) for source in sources]
        for source, view in zip(sources, views, strict=True):
            if not view.stale or source.stale_alerted_at is not None:
                continue
            source.stale_alerted_at = now
            session.add(
                OutboxEvent(
                    tenant_id=tenant_id,
                    type="provisioning_source.stale",
                    aggregate_type="provisioning_source",
                    aggregate_id=source.id,
                    payload={
                        "provisioningSourceId": str(source.id),
                        "key": source.key,
                        "staleAfterSeconds": source.stale_after_seconds,
                        "lastSyncAt": view.last_sync_at.isoformat() if view.last_sync_at else None,
                    },
                )
            )
            session.add(
                AuditEvent(
                    tenant_id=tenant_id,
                    action="provisioning_sources.stale_detected",
                    actor_ref="monitor",
                    resource_type="provisioning_source",
                    resource_id=source.id,
                    outcome="denied",
                    reason=f"source:{source.key}",
                )
            )
        await session.commit()
        return views

    # --- discovery -----------------------------------------------------

    @router.get("/scim/v2/ServiceProviderConfig", tags=["scim"])
    async def scim_service_provider_config(_: ProvisioningService = Depends(provisioning)):
        return _scim(service_provider_config())

    @router.get("/scim/v2/ResourceTypes", tags=["scim"])
    async def scim_resource_types(_: ProvisioningService = Depends(provisioning)):
        return _scim(resource_types())

    @router.get("/scim/v2/Schemas", tags=["scim"])
    async def scim_schemas(_: ProvisioningService = Depends(provisioning)):
        return _scim(schemas_document())

    # --- Users ---------------------------------------------------------

    async def user_payload(service: ProvisioningService, user: ScimUser) -> dict[str, Any]:
        groups = [
            {"value": str(group.id), "display": group.display_name}
            for group in await service.user_groups(user)
        ]
        return user_representation(user, groups=groups)

    @router.get("/scim/v2/Users", tags=["scim"])
    async def scim_list_users(
        filter: str | None = Query(default=None),
        start_index: int = Query(default=1, alias="startIndex"),
        count: int = Query(default=100),
        service: ProvisioningService = Depends(provisioning),
    ):
        start, limit = page(start_index, count)
        terms = parse_filter(filter, allowed=USER_FILTER_ATTRIBUTES) if filter else []
        users, total = await service.query_users(terms, start_index=start, count=limit)
        resources = [await user_payload(service, user) for user in users]
        return _scim(list_response(resources, total=total, start_index=start))

    @router.get("/scim/v2/Users/{user_id}", tags=["scim"])
    async def scim_get_user(
        user_id: uuid.UUID, service: ProvisioningService = Depends(provisioning)
    ):
        user = await service.load_user(user_id)
        return _scim(await user_payload(service, user), version=user.version)

    @router.post("/scim/v2/Users", tags=["scim"])
    async def scim_create_user(
        body: ScimUserRequest, service: ProvisioningService = Depends(provisioning)
    ):
        user = await service.create_user(body)
        service.mark_sync()
        payload = await user_payload(service, user)
        await service.session.commit()
        return _scim(payload, status_code=201, version=user.version)

    @router.put("/scim/v2/Users/{user_id}", tags=["scim"])
    async def scim_replace_user(
        user_id: uuid.UUID,
        body: ScimUserRequest,
        if_match: str = Header(default="", alias="If-Match"),
        service: ProvisioningService = Depends(provisioning),
    ):
        user = await service.load_user(user_id)
        service.ensure_version(user, if_match)
        await service.replace_user(user, body)
        service.mark_sync()
        payload = await user_payload(service, user)
        await service.session.commit()
        return _scim(payload, version=user.version)

    @router.patch("/scim/v2/Users/{user_id}", tags=["scim"])
    async def scim_patch_user(
        user_id: uuid.UUID,
        body: ScimPatchRequest,
        if_match: str = Header(default="", alias="If-Match"),
        service: ProvisioningService = Depends(provisioning),
    ):
        user = await service.load_user(user_id)
        service.ensure_version(user, if_match)
        await service.patch_user(user, body.operations)
        service.mark_sync()
        payload = await user_payload(service, user)
        await service.session.commit()
        return _scim(payload, version=user.version)

    @router.delete("/scim/v2/Users/{user_id}", status_code=204, tags=["scim"])
    async def scim_delete_user(
        user_id: uuid.UUID, service: ProvisioningService = Depends(provisioning)
    ) -> Response:
        user = await service.load_user(user_id)
        await service.deprovision_user(user)
        service.mark_sync()
        await service.session.commit()
        return Response(status_code=204)

    # --- Groups --------------------------------------------------------

    async def group_payload(service: ProvisioningService, group: ScimGroup) -> dict[str, Any]:
        members = [
            {"value": str(member.id), "display": member.user_name, "type": "User"}
            for member in await service.member_users(group)
        ]
        return group_representation(group, members=members)

    @router.get("/scim/v2/Groups", tags=["scim"])
    async def scim_list_groups(
        filter: str | None = Query(default=None),
        start_index: int = Query(default=1, alias="startIndex"),
        count: int = Query(default=100),
        service: ProvisioningService = Depends(provisioning),
    ):
        start, limit = page(start_index, count)
        terms = parse_filter(filter, allowed=GROUP_FILTER_ATTRIBUTES) if filter else []
        groups, total = await service.query_groups(terms, start_index=start, count=limit)
        resources = [await group_payload(service, group) for group in groups]
        return _scim(list_response(resources, total=total, start_index=start))

    @router.get("/scim/v2/Groups/{group_id}", tags=["scim"])
    async def scim_get_group(
        group_id: uuid.UUID, service: ProvisioningService = Depends(provisioning)
    ):
        group = await service.load_group(group_id)
        return _scim(await group_payload(service, group), version=group.version)

    @router.post("/scim/v2/Groups", tags=["scim"])
    async def scim_create_group(
        body: ScimGroupRequest, service: ProvisioningService = Depends(provisioning)
    ):
        group = await service.create_group(body)
        service.mark_sync()
        payload = await group_payload(service, group)
        await service.session.commit()
        return _scim(payload, status_code=201, version=group.version)

    @router.put("/scim/v2/Groups/{group_id}", tags=["scim"])
    async def scim_replace_group(
        group_id: uuid.UUID,
        body: ScimGroupRequest,
        if_match: str = Header(default="", alias="If-Match"),
        service: ProvisioningService = Depends(provisioning),
    ):
        group = await service.load_group(group_id)
        service.ensure_version(group, if_match)
        changed = await service.replace_members(group, [member.value for member in body.members])
        if body.display_name != group.display_name:
            group.display_name = body.display_name
            changed = True
        if changed:
            group.version += 1
            group.updated_at = _now()
        service.mark_sync()
        payload = await group_payload(service, group)
        await service.session.commit()
        return _scim(payload, version=group.version)

    @router.patch("/scim/v2/Groups/{group_id}", tags=["scim"])
    async def scim_patch_group(
        group_id: uuid.UUID,
        body: ScimPatchRequest,
        if_match: str = Header(default="", alias="If-Match"),
        service: ProvisioningService = Depends(provisioning),
    ):
        group = await service.load_group(group_id)
        service.ensure_version(group, if_match)
        await service.patch_group(group, body.operations)
        service.mark_sync()
        payload = await group_payload(service, group)
        await service.session.commit()
        return _scim(payload, version=group.version)

    @router.delete("/scim/v2/Groups/{group_id}", status_code=204, tags=["scim"])
    async def scim_delete_group(
        group_id: uuid.UUID, service: ProvisioningService = Depends(provisioning)
    ) -> Response:
        group = await service.load_group(group_id)
        await service.deprovision_group(group)
        service.mark_sync()
        await service.session.commit()
        return Response(status_code=204)

    return router


__all__ = ["KIND_LDAP", "KIND_SCIM", "create_scim_router"]
