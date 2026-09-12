"""HTTP-клиент IAM для локального плагина.

Platform Access Token предъявляется только IAM и только телом запроса: ни в
URL, ни в query, ни в заголовке он не появляется, поэтому не попадает в
access-логи и в историю прокси. Полученный access token дальше уходит ровно в
один resource service своего audience.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime

import httpx

from iam_client.errors import RemoteError

DEFAULT_TIMEOUT = 10.0


@dataclass(frozen=True)
class Introspection:
    """Несекретный снимок записи PAT для `iam auth status`."""

    tenant_id: str
    principal_id: str
    principal_kind: str
    display_name: str
    credential_id: str
    name: str
    public_prefix: str
    audiences: tuple[str, ...]
    scope_ceiling: tuple[str, ...]
    expires_at: datetime
    issued_at: datetime


@dataclass(frozen=True)
class ExchangedToken:
    """Короткоживущий credential одного audience."""

    access_token: str
    expires_in: int
    audience: str
    scope: tuple[str, ...]
    session_id: uuid.UUID


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class IamClient:
    """Тонкий синхронный клиент IAM.

    `transport` подменяется в тестах, поэтому проверка контракта не требует
    ни сети, ни развёрнутого сервиса.
    """

    def __init__(
        self,
        base_url: str,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._transport = transport
        self._timeout = timeout

    def _post(self, path: str, payload: dict[str, object]) -> httpx.Response:
        try:
            with httpx.Client(
                base_url=self._base_url, transport=self._transport, timeout=self._timeout
            ) as client:
                return client.post(path, json=payload)
        except httpx.HTTPError as exc:
            # Наружу уходит класс ошибки, но не тело запроса: в нём секрет.
            raise RemoteError("iam_unreachable", f"IAM недоступен: {type(exc).__name__}") from exc

    @staticmethod
    def _detail(response: httpx.Response) -> str:
        try:
            body = response.json()
        except ValueError:
            return "unexpected_response"
        detail = body.get("detail") if isinstance(body, dict) else None
        return str(detail) if isinstance(detail, str) else "unexpected_response"

    def _ensure_ok(self, response: httpx.Response) -> None:
        if response.status_code < 400:
            return
        detail = self._detail(response)
        if response.status_code == 401:
            raise RemoteError(
                "invalid_token",
                "IAM не признал Platform Access Token: он отозван, истёк или неизвестен",
                status_code=401,
            )
        if response.status_code == 403:
            raise RemoteError(detail, f"IAM отказал: {detail}", status_code=403)
        raise RemoteError(
            "iam_error",
            f"IAM ответил {response.status_code} ({detail})",
            status_code=response.status_code,
        )

    def introspect(self, token: str) -> Introspection:
        response = self._post("/api/v1/platform-access-tokens:introspect", {"token": token})
        self._ensure_ok(response)
        body = response.json()
        return Introspection(
            tenant_id=body["tenantId"],
            principal_id=body["principalId"],
            principal_kind=body["principalKind"],
            display_name=body["displayName"],
            credential_id=body["credentialId"],
            name=body["name"],
            public_prefix=body["publicPrefix"],
            audiences=tuple(body["audiences"]),
            scope_ceiling=tuple(body["scopeCeiling"]),
            expires_at=_parse_datetime(body["expiresAt"]),
            issued_at=_parse_datetime(body["issuedAt"]),
        )

    def exchange(self, token: str, *, audience: str, scopes: Iterable[str] = ()) -> ExchangedToken:
        payload: dict[str, object] = {"token": token, "audience": audience}
        requested: Sequence[str] = sorted(set(scopes))
        if requested:
            payload["scopes"] = list(requested)
        response = self._post("/api/v1/platform-access-tokens:exchange", payload)
        self._ensure_ok(response)
        body = response.json()
        return ExchangedToken(
            access_token=body["accessToken"],
            expires_in=int(body["expiresIn"]),
            audience=body["audience"],
            scope=tuple(body["scope"]),
            session_id=uuid.UUID(body["sessionId"]),
        )

    def revoke_self(self, token: str, *, reason: str = "logout") -> None:
        response = self._post(
            "/api/v1/platform-access-tokens:revoke-self", {"token": token, "reason": reason}
        )
        self._ensure_ok(response)
