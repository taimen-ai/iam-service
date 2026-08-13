from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm


class FakeIdentityProvider:
    """Локальный OIDC issuer для тестов вместо живого Keycloak.

    Отдаёт discovery, JWKS и подписанные токены, поэтому negative matrix
    (issuer, audience, подпись, алгоритм, expiry) проверяется без сети.
    """

    def __init__(self, issuer: str = "https://idp.example/realms/platform") -> None:
        self.issuer = issuer
        self.audience = "iam-service"
        self.key_id = "idp-key-1"
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/certs"

    @property
    def discovery_uri(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    def discovery_document(self) -> dict[str, Any]:
        return {"issuer": self.issuer, "jwks_uri": self.jwks_uri}

    def jwks_document(self) -> dict[str, Any]:
        key = json.loads(RSAAlgorithm.to_jwk(self.private_key.public_key()))
        key.update({"kid": self.key_id, "use": "sig", "alg": "RS256"})
        return {"keys": [key]}

    def documents(self) -> dict[str, dict[str, Any]]:
        return {
            self.discovery_uri: self.discovery_document(),
            self.jwks_uri: self.jwks_document(),
        }

    def token(
        self,
        *,
        subject: str = "keycloak-subject",
        issuer: str | None = None,
        audience: str | None = None,
        expires_in: int = 300,
        key_id: str | None = None,
        sign_with_foreign_key: bool = False,
        algorithm: str = "RS256",
        claims: dict[str, Any] | None = None,
    ) -> str:
        now = datetime.now(UTC)
        payload: dict[str, Any] = {
            "iss": issuer or self.issuer,
            "sub": subject,
            "aud": audience or self.audience,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(seconds=expires_in),
        }
        payload.update(claims or {})
        headers = {"kid": key_id or self.key_id}
        if algorithm == "HS256":
            return jwt.encode(payload, "shared-secret", algorithm="HS256", headers=headers)
        signing_key = self.foreign_key if sign_with_foreign_key else self.private_key
        return jwt.encode(payload, signing_key, algorithm=algorithm, headers=headers)


class FakeFetcher:
    """Транспорт до IdP с управляемой недоступностью."""

    def __init__(self, documents: dict[str, dict[str, Any]]) -> None:
        self.documents = documents
        self.available = True
        self.calls: list[str] = []

    async def fetch_json(self, url: str) -> dict[str, Any]:
        self.calls.append(url)
        if not self.available:
            raise ConnectionError("identity provider is unreachable")
        try:
            return self.documents[url]
        except KeyError as exc:
            raise ValueError(f"unknown document: {url}") from exc


@pytest.fixture
def idp() -> FakeIdentityProvider:
    return FakeIdentityProvider()


@pytest.fixture
def fetcher(idp: FakeIdentityProvider) -> FakeFetcher:
    return FakeFetcher(idp.documents())
