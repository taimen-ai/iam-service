"""Драйвер записи в upstream Keycloak.

ADR-0012 фиксирует, что native SCIM API Keycloak на момент решения имеет статус
Preview. Поэтому adapter умеет обе дороги: SCIM endpoint и стабильный Admin API.
Режим `auto` пробует SCIM и падает обратно на Admin API, если endpoint не
развёрнут или временно недоступен. Контракт IAM и resource services от выбора
дороги не зависит — переход на stable native SCIM его не меняет.

Транспорт инъектируется, поэтому fallback проверяется тестами без сети.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from iam_service.scim.models import UPSTREAM_ADMIN, UPSTREAM_AUTO, UPSTREAM_SCIM

# Статусы, при которых имеет смысл пробовать вторую дорогу: endpoint не
# развёрнут, отключён флагом или временно недоступен.
_FALLBACK_STATUSES = frozenset({404, 405, 501, 502, 503})


class UpstreamUnavailable(Exception):
    """Upstream не принял запись. Провижининг закрывается, а не расходится."""


@dataclass(frozen=True)
class UpstreamResponse:
    status_code: int
    payload: dict[str, Any]
    location: str | None = None


class UpstreamTransport(Protocol):
    """HTTP до Keycloak. Подменяется в тестах и degraded-сценариях."""

    async def send(
        self, method: str, url: str, *, json: dict[str, Any] | None = None
    ) -> UpstreamResponse: ...


class HttpUpstreamTransport:
    def __init__(self, *, timeout_seconds: float = 5.0) -> None:
        self.timeout_seconds = timeout_seconds

    async def send(
        self, method: str, url: str, *, json: dict[str, Any] | None = None
    ) -> UpstreamResponse:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.request(method, url, json=json)
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        return UpstreamResponse(
            status_code=response.status_code,
            payload=payload if isinstance(payload, dict) else {},
            location=response.headers.get("location"),
        )


@dataclass(frozen=True)
class UpstreamUser:
    """Результат записи в upstream: id пользователя и использованная дорога."""

    user_id: str | None
    via: str


class NullProvisioningDriver:
    """Режим `off`: IAM ведёт только собственную проекцию.

    Применим, когда SCIM-клиент уже пишет в Keycloak сам, а IAM получает те же
    вызовы для построения Principal и групп.
    """

    async def create_user(self, *, external_id: str, user_name: str, active: bool) -> UpstreamUser:
        return UpstreamUser(user_id=None, via="none")

    async def set_user_active(self, *, user_id: str | None, active: bool) -> UpstreamUser:
        return UpstreamUser(user_id=user_id, via="none")


class KeycloakProvisioningDriver:
    """Запись в Keycloak через SCIM endpoint либо Admin API."""

    def __init__(
        self, transport: UpstreamTransport, *, base_url: str, realm: str, mode: str
    ) -> None:
        self.transport = transport
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self.mode = mode

    def _scim_url(self, path: str = "") -> str:
        return f"{self.base_url}/realms/{self.realm}/scim/v2/Users{path}"

    def _admin_url(self, path: str = "") -> str:
        return f"{self.base_url}/admin/realms/{self.realm}/users{path}"

    async def create_user(self, *, external_id: str, user_name: str, active: bool) -> UpstreamUser:
        async def via_scim() -> UpstreamResponse:
            return await self.transport.send(
                "POST",
                self._scim_url(),
                json={
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "externalId": external_id,
                    "userName": user_name,
                    "active": active,
                },
            )

        async def via_admin() -> UpstreamResponse:
            return await self.transport.send(
                "POST",
                self._admin_url(),
                json={
                    "username": user_name,
                    "enabled": active,
                    # Стабильный внешний идентификатор переносится атрибутом:
                    # Admin API не знает поля externalId.
                    "attributes": {"externalId": [external_id]},
                },
            )

        response, via = await self._attempt(via_scim, via_admin)
        return UpstreamUser(user_id=_user_id(response), via=via)

    async def set_user_active(self, *, user_id: str | None, active: bool) -> UpstreamUser:
        if user_id is None:
            raise UpstreamUnavailable("upstream user id is unknown")

        async def via_scim() -> UpstreamResponse:
            return await self.transport.send(
                "PATCH",
                self._scim_url(f"/{user_id}"),
                json={
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": [{"op": "replace", "path": "active", "value": active}],
                },
            )

        async def via_admin() -> UpstreamResponse:
            return await self.transport.send(
                "PUT", self._admin_url(f"/{user_id}"), json={"enabled": active}
            )

        _, via = await self._attempt(via_scim, via_admin)
        return UpstreamUser(user_id=user_id, via=via)

    async def _attempt(self, scim_call, admin_call) -> tuple[UpstreamResponse, str]:
        if self.mode == UPSTREAM_ADMIN:
            return await self._call(admin_call, "admin"), "admin"
        if self.mode == UPSTREAM_SCIM:
            return await self._call(scim_call, "scim"), "scim"
        if self.mode != UPSTREAM_AUTO:
            raise UpstreamUnavailable(f"unknown upstream mode: {self.mode}")
        try:
            return await self._call(scim_call, "scim"), "scim"
        except UpstreamUnavailable:
            return await self._call(admin_call, "admin"), "admin"

    async def _call(self, call, road: str) -> UpstreamResponse:
        try:
            response = await call()
        except Exception as exc:  # транспортная ошибка — та же деградация
            raise UpstreamUnavailable(f"{road} road is unreachable") from exc
        if response.status_code in _FALLBACK_STATUSES:
            raise UpstreamUnavailable(f"{road} road returned {response.status_code}")
        if response.status_code >= 400:
            raise UpstreamUnavailable(f"{road} road rejected the write: {response.status_code}")
        return response


def build_driver(
    source: Any, transport: UpstreamTransport | None
) -> NullProvisioningDriver | KeycloakProvisioningDriver:
    if source.upstream_mode == "off" or not source.upstream_base_url:
        return NullProvisioningDriver()
    return KeycloakProvisioningDriver(
        transport or HttpUpstreamTransport(),
        base_url=source.upstream_base_url,
        realm=source.upstream_realm,
        mode=source.upstream_mode,
    )


def _user_id(response: UpstreamResponse) -> str | None:
    identifier = response.payload.get("id")
    if isinstance(identifier, str) and identifier:
        return identifier
    # Admin API возвращает пустое тело и Location с идентификатором.
    if response.location:
        return response.location.rstrip("/").rsplit("/", 1)[-1]
    return None
