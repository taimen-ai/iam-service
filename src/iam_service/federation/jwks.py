from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

import httpx
import jwt

from iam_service.federation.errors import FederationError

DISCOVERY_PATH = "/.well-known/openid-configuration"


class JsonFetcher(Protocol):
    """Транспорт до upstream IdP. Подменяется в тестах и degraded-сценариях."""

    async def fetch_json(self, url: str) -> dict[str, Any]: ...


class HttpJsonFetcher:
    def __init__(self, *, timeout_seconds: float = 5.0) -> None:
        self.timeout_seconds = timeout_seconds

    async def fetch_json(self, url: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.get(url)
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("identity provider returned a non-object document")
        return payload


@dataclass(frozen=True)
class ResolvedJwks:
    keys: jwt.PyJWKSet
    fetched_at: datetime
    stale: bool


@dataclass
class _CacheEntry:
    jwks_uri: str
    keys: jwt.PyJWKSet
    fetched_at: datetime


class JwksResolver:
    """Discovery и JWKS с bounded degraded-mode.

    Свежий кэш отдаётся без сетевого вызова. Если upstream недоступен, кэш
    отдаётся как `stale` только внутри grace window провайдера; после него
    federation закрывается (fail closed), а не продолжает доверять ключам.
    """

    def __init__(self, fetcher: JsonFetcher | None = None) -> None:
        self.fetcher = fetcher or HttpJsonFetcher()
        self._entries: dict[uuid.UUID, _CacheEntry] = {}

    async def resolve(
        self,
        *,
        provider_id: uuid.UUID,
        issuer: str,
        jwks_uri: str,
        cache_ttl_seconds: int,
        stale_grace_seconds: int,
    ) -> ResolvedJwks:
        now = datetime.now(UTC)
        entry = self._entries.get(provider_id)
        if entry is not None and (now - entry.fetched_at).total_seconds() < cache_ttl_seconds:
            return ResolvedJwks(keys=entry.keys, fetched_at=entry.fetched_at, stale=False)

        try:
            resolved_uri = jwks_uri or await self._discover_jwks_uri(issuer)
            document = await self.fetcher.fetch_json(resolved_uri)
            keys = jwt.PyJWKSet.from_dict(document)
        except Exception as exc:
            if entry is None:
                raise FederationError("identity_provider_unavailable", status_code=503) from exc
            age = (now - entry.fetched_at).total_seconds()
            if age >= cache_ttl_seconds + stale_grace_seconds:
                raise FederationError("identity_provider_unavailable", status_code=503) from exc
            return ResolvedJwks(keys=entry.keys, fetched_at=entry.fetched_at, stale=True)

        self._entries[provider_id] = _CacheEntry(jwks_uri=resolved_uri, keys=keys, fetched_at=now)
        return ResolvedJwks(keys=keys, fetched_at=now, stale=False)

    async def _discover_jwks_uri(self, issuer: str) -> str:
        document = await self.fetcher.fetch_json(f"{issuer.rstrip('/')}{DISCOVERY_PATH}")
        if document.get("issuer") != issuer:
            raise ValueError("discovery document issuer mismatch")
        jwks_uri = document.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri:
            raise ValueError("discovery document has no jwks_uri")
        return jwks_uri
