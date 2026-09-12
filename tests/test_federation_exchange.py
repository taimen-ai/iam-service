"""`federation:exchange` — вход через upstream IdP плюс credential одного audience.

Маршрут нужен шлюзу, действующему от имени человека в браузере: у того нет
Platform Access Token, только upstream token. Проверяется, что выданный token
имеет ту же форму, что при обмене PAT (подпись из JWKS IAM, `aud`, `sub`,
`tenant_id`, `principal_type`, `scope`, `auth_time`, `acr`, `session_id`), что
identity не дублируется, а отказы по audience и scope закрывают выпуск и
попадают в audit.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from conftest import FakeFetcher, FakeIdentityProvider
from iam_service.app import create_app
from iam_service.config import Settings

BOOTSTRAP = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}
ISSUER = "https://iam.example"
AUDIENCE_SCOPES = {"control-plane": ["control-plane:read", "control-plane:write"]}


def signing_key_pem() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


class Harness:
    def __init__(self, client: TestClient, database_path) -> None:
        self.client = client
        self.database_path = database_path
        self.tenant_id = ""

    def register(self, idp: FakeIdentityProvider, **provider_overrides: Any) -> str:
        tenant = self.client.post(
            "/api/v1/tenants", headers=BOOTSTRAP, json={"slug": "tenant-a", "name": "A"}
        ).json()
        self.tenant_id = tenant["id"]
        for key, scopes in AUDIENCE_SCOPES.items():
            response = self.client.post(
                f"/api/v1/tenants/{self.tenant_id}/audiences",
                headers=BOOTSTRAP,
                json={"key": key, "allowedScopes": scopes},
            )
            assert response.status_code == 201, response.text
        body: dict[str, Any] = {
            "key": "keycloak",
            "issuer": idp.issuer,
            "audience": idp.audience,
            "groupMappings": {"platform-operators": "operators"},
        }
        body.update(provider_overrides)
        provider = self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/identity-providers", headers=BOOTSTRAP, json=body
        )
        assert provider.status_code == 201, provider.text
        return self.tenant_id

    def exchange(
        self,
        token: str,
        *,
        audience: str = "control-plane",
        scopes: list[str] | None = None,
        provider: str = "keycloak",
    ):
        return self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/federation:exchange",
            json={
                "identityProvider": provider,
                "token": token,
                "audience": audience,
                "scopes": scopes or [],
            },
        )

    def authenticate(self, token: str):
        return self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/federation:authenticate",
            json={"identityProvider": "keycloak", "token": token},
        )

    def claims(self, access_token: str, *, audience: str = "control-plane") -> dict[str, Any]:
        """Проверить подпись ключом из JWKS IAM — как это делает resource service."""

        header = jwt.get_unverified_header(access_token)
        jwks = jwt.PyJWKSet.from_dict(self.client.get("/.well-known/jwks.json").json())
        return dict(
            jwt.decode(
                access_token,
                jwks[header["kid"]].key,
                algorithms=["RS256"],
                issuer=ISSUER,
                audience=audience,
                options={"require": ["iss", "sub", "tenant_id", "aud", "iat", "nbf", "exp", "jti"]},
            )
        )

    def events(self) -> list[str]:
        items = self.client.get("/api/v1/events", headers=BOOTSTRAP).json()["items"]
        return [event["type"] for event in items]

    def audit(self) -> list[tuple[str, str, str, str]]:
        with sqlite3.connect(self.database_path) as connection:
            return list(
                connection.execute(
                    "SELECT action, actor_ref, outcome, reason FROM audit_events ORDER BY rowid"
                )
            )


@pytest.fixture
def harness(tmp_path, fetcher: FakeFetcher):
    database_path = tmp_path / "iam.db"
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{database_path}",
        bootstrap_token="test-bootstrap-token",
        issuer=ISSUER,
        signing_private_key=signing_key_pem(),
        create_schema_on_startup=True,
    )
    with TestClient(create_app(settings, jwks_fetcher=fetcher)) as client:
        yield Harness(client, database_path)


def test_exchange_issues_audience_token_with_human_authentication_context(
    harness: Harness, idp: FakeIdentityProvider
) -> None:
    harness.register(idp)
    token = idp.token(
        claims={
            "groups": ["/platform-operators", "/finance-admins"],
            "acr": "silver",
            "amr": ["pwd", "otp"],
            "auth_time": 1_760_000_000,
        }
    )

    response = harness.exchange(token, scopes=["control-plane:read"])

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["tokenType"] == "Bearer"
    assert body["expiresIn"] == 300
    assert body["audience"] == "control-plane"
    assert body["scope"] == ["control-plane:read"]
    assert body["identityProvider"] == "keycloak"
    assert body["groups"] == ["operators"]
    assert body["authenticationContext"]["acr"] == "silver"
    assert body["authenticationContext"]["amr"] == ["pwd", "otp"]
    assert body["authenticationContext"]["authTime"] is not None
    assert body["identityProviderStale"] is False

    claims = harness.claims(body["accessToken"])
    assert claims["aud"] == "control-plane"
    assert claims["sub"] == body["principalId"]
    assert claims["tenant_id"] == harness.tenant_id
    assert claims["principal_type"] == "human"
    assert claims["scope"] == ["control-plane:read"]
    assert claims["scope_ceiling"] == ["control-plane:read", "control-plane:write"]
    assert claims["session_id"] == body["sessionId"]
    assert claims["acr"] == "silver"
    # `auth_time` — ISO 8601, как в токене после обмена PAT: SDK resource
    # service разбирает именно этот формат.
    assert claims["auth_time"].startswith("2025-10-09T")
    assert "credential_id" in claims
    # Token одного audience: под чужим audience он не проходит.
    with pytest.raises(jwt.InvalidAudienceError):
        harness.claims(body["accessToken"], audience="memory-service")


def test_repeated_exchange_keeps_one_principal(harness: Harness, idp: FakeIdentityProvider) -> None:
    harness.register(idp)
    token = idp.token(claims={"acr": "1"})

    first = harness.exchange(token)
    second = harness.exchange(token)
    # Обычный вход и обмен — одна и та же identity, а не две.
    login = harness.authenticate(token)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()["principalId"] == second.json()["principalId"]
    assert login.json()["principalId"] == first.json()["principalId"]
    assert first.json()["sessionId"] != second.json()["sessionId"]
    assert harness.events().count("principal.created") == 1
    first_claims = harness.claims(first.json()["accessToken"])
    second_claims = harness.claims(second.json()["accessToken"])
    # credential_id стабилен между обменами: это id external identity, по
    # которому resource service ведёт свой revocation-кэш.
    assert first_claims["credential_id"] == second_claims["credential_id"]


def test_unknown_audience_is_refused(harness: Harness, idp: FakeIdentityProvider) -> None:
    harness.register(idp)

    response = harness.exchange(idp.token(), audience="memory-service")

    assert response.status_code == 403
    assert response.json()["detail"] == "audience_not_allowed"
    assert "accessToken" not in response.text
    # Identity подтверждена и остаётся: отказ касается credential, не входа.
    assert harness.events().count("principal.created") == 1


def test_scope_outside_audience_allowlist_is_refused(
    harness: Harness, idp: FakeIdentityProvider
) -> None:
    harness.register(idp)

    response = harness.exchange(idp.token(), scopes=["control-plane:read", "control-plane:admin"])

    assert response.status_code == 403
    assert response.json()["detail"] == "scope_not_allowed"
    assert "accessToken" not in response.text


def test_empty_scopes_mean_the_whole_audience_allowlist(
    harness: Harness, idp: FakeIdentityProvider
) -> None:
    harness.register(idp)

    response = harness.exchange(idp.token(), scopes=[])

    assert response.status_code == 200, response.text
    assert response.json()["scope"] == ["control-plane:read", "control-plane:write"]
    claims = harness.claims(response.json()["accessToken"])
    assert claims["scope"] == ["control-plane:read", "control-plane:write"]
    assert claims["scope_ceiling"] == claims["scope"]


@pytest.mark.parametrize(
    ("token_kwargs", "expected_status", "expected_detail"),
    [
        ({"issuer": "https://attacker.example"}, 401, "invalid_issuer"),
        ({"audience": "another-service"}, 401, "invalid_audience"),
        ({"sign_with_foreign_key": True}, 401, "invalid_signature"),
        ({"algorithm": "HS256"}, 401, "unsupported_algorithm"),
        ({"key_id": "rotated-away"}, 401, "unknown_signing_key"),
        ({"expires_in": -60}, 401, "token_expired"),
    ],
)
def test_untrusted_upstream_tokens_get_the_same_answer_as_authenticate(
    harness: Harness,
    idp: FakeIdentityProvider,
    token_kwargs: dict[str, Any],
    expected_status: int,
    expected_detail: str,
) -> None:
    harness.register(idp)

    exchanged = harness.exchange(idp.token(**token_kwargs))
    authenticated = harness.authenticate(idp.token(**token_kwargs))

    assert exchanged.status_code == expected_status
    assert exchanged.json()["detail"] == expected_detail
    assert (authenticated.status_code, authenticated.json()["detail"]) == (
        exchanged.status_code,
        exchanged.json()["detail"],
    )
    assert "principal.created" not in harness.events()


def test_unknown_provider_and_step_up_follow_authenticate(
    harness: Harness, idp: FakeIdentityProvider
) -> None:
    harness.register(idp, requiredAcrValues=["mfa"])

    unknown_provider = harness.exchange(idp.token(claims={"acr": "mfa"}), provider="okta")
    single_factor = harness.exchange(idp.token(claims={"acr": "1"}))
    stepped_up = harness.exchange(idp.token(claims={"acr": "mfa"}))

    assert unknown_provider.status_code == 404
    assert unknown_provider.json()["detail"] == "identity_provider_not_found"
    assert single_factor.status_code == 403
    assert single_factor.json()["detail"] == "step_up_required"
    assert stepped_up.status_code == 200, stepped_up.text


def test_password_credentials_are_not_part_of_the_exchange_contract(
    harness: Harness, idp: FakeIdentityProvider
) -> None:
    harness.register(idp)

    response = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/federation:exchange",
        json={
            "identityProvider": "keycloak",
            "token": idp.token(),
            "audience": "control-plane",
            "password": "ldap-secret-value",
        },
    )

    assert response.status_code == 422
    assert "ldap-secret-value" not in harness.client.get("/api/v1/events", headers=BOOTSTRAP).text


def test_audit_records_exchange_outcomes_without_the_token(
    harness: Harness, idp: FakeIdentityProvider
) -> None:
    harness.register(idp)
    upstream = idp.token(claims={"acr": "silver"})

    allowed = harness.exchange(upstream, scopes=["control-plane:read"])
    denied_audience = harness.exchange(upstream, audience="memory-service")
    denied_scope = harness.exchange(upstream, scopes=["control-plane:admin"])
    denied_upstream = harness.exchange(idp.token(sign_with_foreign_key=True))

    assert allowed.status_code == 200
    assert denied_audience.status_code == 403
    assert denied_scope.status_code == 403
    assert denied_upstream.status_code == 401
    principal_id = allowed.json()["principalId"]
    session_id = allowed.json()["sessionId"]

    audit = harness.audit()
    exchange_rows = [row for row in audit if row[0] == "federation.exchange"]
    assert [row[2] for row in exchange_rows] == ["allowed", "denied", "denied", "denied"]
    assert exchange_rows[0][1] == principal_id
    assert exchange_rows[0][3] == f"provider:keycloak audience:control-plane session:{session_id}"
    assert exchange_rows[1][3] == "provider:keycloak audience:memory-service audience_not_allowed"
    assert exchange_rows[2][3] == "provider:keycloak audience:control-plane scope_not_allowed"
    assert exchange_rows[3][1] == "provider:keycloak"
    assert exchange_rows[3][3] == "invalid_signature"
    # Отказ выпуска не маскируется под отказ входа: `federation.authenticate`
    # здесь не появляется вовсе.
    assert all(row[0] != "federation.authenticate" for row in audit)
    dump = str(audit)
    assert allowed.json()["accessToken"] not in dump
    assert upstream not in dump


def test_non_human_principal_cannot_exchange(harness: Harness, idp: FakeIdentityProvider) -> None:
    """Federation сама заводит только human; иной вид — ручная привязка."""

    harness.register(idp, lifecycleProfile="managed")
    service_account = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/principals",
        headers=BOOTSTRAP,
        json={"kind": "service_account", "displayName": "Robot"},
    ).json()
    linked = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{service_account['id']}/external-identities",
        headers=BOOTSTRAP,
        json={"issuer": idp.issuer, "subject": "robot-subject"},
    )
    assert linked.status_code == 201, linked.text

    response = harness.exchange(idp.token(subject="robot-subject"))

    assert response.status_code == 422
    assert response.json()["detail"] == "human_principal_required"
    assert "accessToken" not in response.text
    assert any(
        row[0] == "federation.exchange"
        and row[2] == "denied"
        and "human_principal_required" in row[3]
        for row in harness.audit()
    )
