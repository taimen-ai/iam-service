"""Канал (Telegram) как способ входа человека.

Путь целиком: человек со своим token IAM получает код привязки, адаптер
канала (service account со scope `iam:channel-links`) подтверждает код и
потом обменивает assertion на token одного решения. Проверяется форма token
(контракт с `platform-auth-sdk`) и negative matrix: чужой, просроченный и
использованный код, отключённый провайдер, отвязанный аккаунт, principal-агент,
чужой предъявитель, лимиты частоты.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from conftest import FakeFetcher, FakeIdentityProvider
from iam_service.app import create_app
from iam_service.channels import channel_issuer
from iam_service.config import Settings
from iam_service.tokens import TokenIssuer

BOOTSTRAP = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}
ISSUER = "https://iam.example"
TELEGRAM_USER = "100200300"

# Контракт `platform-auth-sdk` (platform_auth/verify.py, REQUIRED_CLAIMS):
# без любого из этих claims resource service token не примет.
SDK_REQUIRED_CLAIMS = ("iss", "sub", "aud", "tenant_id", "iat", "nbf", "exp", "jti")


def sqlite_time(value: datetime) -> str:
    """Формат, в котором SQLAlchemy хранит DateTime в SQLite."""

    return value.strftime("%Y-%m-%d %H:%M:%S.%f")


def signing_key_pem() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


class Harness:
    def __init__(self, client: TestClient, database_path, settings: Settings) -> None:
        self.client = client
        self.database_path = database_path
        self.settings = settings
        self.tenant_id = ""

    # --- подготовка ----------------------------------------------------

    def tenant(self, slug: str = "tenant-a", *, decide_scope: bool = True) -> str:
        tenant_id = self.client.post(
            "/api/v1/tenants", headers=BOOTSTRAP, json={"slug": slug, "name": slug}
        ).json()["id"]
        control_plane_scopes = ["control-plane:read"]
        if decide_scope:
            control_plane_scopes.append("control-plane:decide")
        for key, scopes in {
            "iam": ["iam:channel-links"],
            "control-plane": control_plane_scopes,
        }.items():
            response = self.client.post(
                f"/api/v1/tenants/{tenant_id}/audiences",
                headers=BOOTSTRAP,
                json={"key": key, "allowedScopes": scopes},
            )
            assert response.status_code == 201, response.text
        self.tenant_id = self.tenant_id or tenant_id
        return tenant_id

    def provider(self, status: str = "active", *, tenant_id: str | None = None):
        response = self.client.put(
            f"/api/v1/tenants/{tenant_id or self.tenant_id}/channel-providers/telegram",
            headers=BOOTSTRAP,
            json={"status": status},
        )
        assert response.status_code == 200, response.text
        return response.json()

    def principal(self, kind: str = "human", *, tenant_id: str | None = None) -> str:
        response = self.client.post(
            f"/api/v1/tenants/{tenant_id or self.tenant_id}/principals",
            headers=BOOTSTRAP,
            json={"kind": kind, "displayName": f"{kind} principal"},
        )
        assert response.status_code == 201, response.text
        return response.json()["id"]

    def mint(
        self,
        principal_id: str,
        *,
        principal_type: str = "human",
        tenant_id: str | None = None,
        audience: str = "iam",
        scopes: list[str] | None = None,
        auth_time: datetime | None = None,
        acr: str | None = None,
        credential_id: str | None = None,
    ) -> dict[str, str]:
        """Token IAM для человека или агента — тем же ключом, что у сервиса."""

        token = TokenIssuer(
            issuer=ISSUER,
            private_key=self.settings.signing_private_key,
            key_id=self.settings.signing_key_id,
            ttl_seconds=300,
        ).issue(
            subject=uuid.UUID(principal_id),
            tenant_id=uuid.UUID(tenant_id or self.tenant_id),
            audience=audience,
            scopes=scopes or [],
            credential_id=uuid.UUID(credential_id) if credential_id else uuid.uuid4(),
            principal_type=principal_type,
            auth_time=(auth_time or datetime.now(UTC)).isoformat(),
            acr=acr,
        )
        return {"Authorization": f"Bearer {token}"}

    def adapter(
        self,
        *,
        tenant_id: str | None = None,
        scopes: list[str] | None = None,
    ) -> tuple[dict[str, str], str]:
        """Service account адаптера канала и его token для audience IAM."""

        tenant_id = tenant_id or self.tenant_id
        account = self.client.post(
            f"/api/v1/tenants/{tenant_id}/service-accounts",
            headers=BOOTSTRAP,
            json={
                "displayName": "telegram adapter",
                "audiences": ["iam"],
                "scopeCeiling": ["iam:channel-links"],
            },
        ).json()
        response = self.client.post(
            "/api/v1/tokens/exchange",
            json={
                "clientId": account["clientId"],
                "clientSecret": account["clientSecret"],
                "audience": "iam",
                "scopes": ["iam:channel-links"] if scopes is None else scopes,
            },
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['accessToken']}"}, account["clientId"]

    # --- шаги ----------------------------------------------------------

    def intent(self, headers: dict[str, str], *, tenant_id: str | None = None):
        return self.client.post(
            f"/api/v1/tenants/{tenant_id or self.tenant_id}/channel-link-intents",
            headers=headers,
            json={"channel": "telegram"},
        )

    def confirm(
        self,
        headers: dict[str, str],
        code: str,
        *,
        subject: str = TELEGRAM_USER,
        tenant_id: str | None = None,
    ):
        return self.client.post(
            f"/api/v1/tenants/{tenant_id or self.tenant_id}/channel-links:confirm",
            headers=headers,
            json={"channel": "telegram", "code": code, "externalSubject": subject},
        )

    def exchange(
        self,
        headers: dict[str, str],
        *,
        subject: str = TELEGRAM_USER,
        purpose: str = "approval:42",
        tenant_id: str | None = None,
    ):
        return self.client.post(
            f"/api/v1/tenants/{tenant_id or self.tenant_id}/channel-assertions:exchange",
            headers=headers,
            json={"channel": "telegram", "externalSubject": subject, "purposeRef": purpose},
        )

    def link(self, human: dict[str, str], adapter: dict[str, str], subject: str = TELEGRAM_USER):
        code = self.intent(human).json()["code"]
        response = self.confirm(adapter, code, subject=subject)
        assert response.status_code == 200, response.text
        return response.json()

    # --- наблюдение ----------------------------------------------------

    def claims(self, access_token: str, *, audience: str = "control-plane") -> dict[str, Any]:
        """Проверить token так, как это делает resource service через SDK."""

        header = jwt.get_unverified_header(access_token)
        jwks = jwt.PyJWKSet.from_dict(self.client.get("/.well-known/jwks.json").json())
        return dict(
            jwt.decode(
                access_token,
                jwks[header["kid"]].key,
                algorithms=["RS256", "RS384", "RS512"],
                issuer=ISSUER,
                audience=audience,
                options={"require": list(SDK_REQUIRED_CLAIMS)},
            )
        )

    def sql(self, statement: str, *params: Any) -> list[tuple]:
        with sqlite3.connect(self.database_path) as connection:
            return list(connection.execute(statement, params))

    def audit(self, action: str) -> list[tuple[str, str]]:
        return [
            (outcome, reason)
            for outcome, reason in self.sql(
                "SELECT outcome, reason FROM audit_events WHERE action = ? ORDER BY rowid", action
            )
        ]

    def events(self) -> list[str]:
        items = self.client.get("/api/v1/events", headers=BOOTSTRAP).json()["items"]
        return [event["type"] for event in items]


def build_harness(tmp_path, fetcher: FakeFetcher | None = None, **overrides: Any):
    database_path = tmp_path / "iam.db"
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{database_path}",
        bootstrap_token="test-bootstrap-token",
        issuer=ISSUER,
        signing_private_key=signing_key_pem(),
        create_schema_on_startup=True,
        **overrides,
    )
    client = TestClient(create_app(settings, jwks_fetcher=fetcher))
    return client, Harness(client, database_path, settings)


@pytest.fixture
def harness(tmp_path, fetcher: FakeFetcher):
    client, harness = build_harness(tmp_path, fetcher)
    with client:
        yield harness


@pytest.fixture
def linked(harness: Harness):
    """Tenant с включённым Telegram, человеком и привязанным аккаунтом."""

    harness.tenant()
    harness.provider()
    principal_id = harness.principal()
    human = harness.mint(principal_id)
    adapter, _ = harness.adapter()
    link = harness.link(human, adapter)
    return {"principal": principal_id, "human": human, "adapter": adapter, "link": link}


# --- основной путь ---------------------------------------------------------


def test_federated_human_links_telegram_and_decides_with_short_lived_token(
    harness: Harness, idp: FakeIdentityProvider
) -> None:
    tenant_id = harness.tenant()
    harness.client.post(
        f"/api/v1/tenants/{tenant_id}/identity-providers",
        headers=BOOTSTRAP,
        json={"key": "keycloak", "issuer": idp.issuer, "audience": idp.audience},
    )
    harness.provider()
    # Человек входит через IdP и получает token для audience IAM — так же, как
    # веб-консоль получает его через шлюз.
    federated = harness.client.post(
        f"/api/v1/tenants/{tenant_id}/federation:exchange",
        json={
            "identityProvider": "keycloak",
            "token": idp.token(claims={"acr": "mfa", "amr": ["pwd", "otp"]}),
            "audience": "iam",
        },
    ).json()
    human = {"Authorization": f"Bearer {federated['accessToken']}"}
    contexts_before = harness.sql("SELECT count(*) FROM authentication_contexts")[0][0]

    intent = harness.intent(human)
    assert intent.status_code == 201, intent.text
    issued = intent.json()
    assert issued["channel"] == "telegram" and len(issued["code"]) >= 32
    # Сервер хранит только hash кода.
    assert harness.sql("SELECT code_hash FROM channel_link_intents")[0][0] != issued["code"]

    adapter, _ = harness.adapter()
    confirmed = harness.confirm(adapter, issued["code"])
    assert confirmed.status_code == 200, confirmed.text
    link = confirmed.json()
    assert link["principalId"] == federated["principalId"]
    assert link["status"] == "active"

    response = harness.exchange(adapter, purpose="approval:7f3c")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["expiresIn"] == 60
    assert body["audience"] == "control-plane"
    assert body["scope"] == ["control-plane:decide"]
    assert body["principalId"] == federated["principalId"]

    claims = harness.claims(body["accessToken"])
    assert claims["sub"] == federated["principalId"]
    assert claims["tenant_id"] == tenant_id
    assert claims["principal_type"] == "human"
    assert claims["acr"] == "channel:telegram"
    assert claims["amr"] == ["channel:telegram"]
    assert claims["scope"] == ["control-plane:decide"]
    assert claims["scope_ceiling"] == ["control-plane:decide"]
    assert claims["purpose_ref"] == "approval:7f3c"
    assert claims["credential_id"] == link["linkId"]
    assert claims["exp"] - claims["iat"] == 60

    # Канал не открывает выпуск PAT: снимок human authentication не пишется.
    assert harness.sql("SELECT count(*) FROM authentication_contexts")[0][0] == contexts_before
    assert {"channel_provider.updated", "channel_link_intent.created"} <= set(harness.events())
    assert "channel_link.confirmed" in harness.events()
    [(outcome, reason)] = harness.audit("channel_assertions.exchange")
    assert outcome == "allowed"
    assert "purpose:approval:7f3c" in reason and federated["principalId"] in reason
    # Ни код, ни id аккаунта Telegram в журнал не попадают.
    journal = " ".join(
        reason for _, reason in harness.sql("SELECT action, reason FROM audit_events")
    )
    assert issued["code"] not in journal and TELEGRAM_USER not in journal


def test_channel_token_satisfies_platform_auth_sdk_contract(harness: Harness, linked) -> None:
    """Форма token — контракт с `platform-auth-sdk` (TrustedAuthContext.from_claims)."""

    token = harness.exchange(linked["adapter"]).json()["accessToken"]
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256" and header["kid"]
    claims = harness.claims(token)
    for name in SDK_REQUIRED_CLAIMS:
        assert claims.get(name), name
    # SDK принимает только audience-строку, а не список.
    assert isinstance(claims["aud"], str)
    uuid.UUID(claims["tenant_id"])
    uuid.UUID(claims["sub"])
    uuid.UUID(claims["credential_id"])
    uuid.UUID(claims["session_id"])
    assert isinstance(claims["scope"], list)
    # auth_time читается SDK как ISO 8601.
    assert datetime.fromisoformat(claims["auth_time"]).tzinfo is not None
    assert isinstance(claims["amr"], list)
    assert isinstance(claims["purpose_ref"], str)


def test_relink_after_revoke_and_link_listing(harness: Harness, linked) -> None:
    human, adapter = linked["human"], linked["adapter"]
    listed = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/channel-links", headers=human
    ).json()
    assert [item["linkId"] for item in listed] == [linked["link"]["linkId"]]

    # Второй аккаунт при действующей привязке — отказ: сначала отзыв.
    assert harness.intent(human).status_code == 409

    revoked = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/channel-links/{linked['link']['linkId']}:revoke",
        headers=human,
    )
    assert revoked.status_code == 204
    assert "channel_link.revoked" in harness.events()

    # Тот же аккаунт Telegram теперь может привязать другой человек.
    other = harness.mint(harness.principal())
    relinked = harness.link(other, adapter)
    assert relinked["principalId"] != linked["principal"]
    assert harness.exchange(adapter).json()["principalId"] == relinked["principalId"]


# --- код привязки ----------------------------------------------------------


def test_foreign_expired_used_and_unknown_codes_are_refused_alike(
    harness: Harness,
) -> None:
    harness.tenant()
    harness.provider()
    other_tenant = harness.tenant("tenant-b")
    harness.provider(tenant_id=other_tenant)
    human = harness.mint(harness.principal())
    adapter, _ = harness.adapter()

    foreign_code = harness.intent(
        harness.mint(harness.principal(tenant_id=other_tenant), tenant_id=other_tenant),
        tenant_id=other_tenant,
    ).json()["code"]
    expired_code = harness.intent(human).json()["code"]
    harness.sql(
        "UPDATE channel_link_intents SET expires_at = ? WHERE rowid = 2",
        sqlite_time(datetime.now(UTC) - timedelta(seconds=1)),
    )
    used_code = harness.intent(human).json()["code"]
    assert harness.confirm(adapter, used_code).status_code == 200

    responses = [
        harness.confirm(adapter, foreign_code, subject="1"),
        harness.confirm(adapter, expired_code, subject="2"),
        harness.confirm(adapter, used_code, subject="3"),
        harness.confirm(adapter, "no-such-code", subject="4"),
    ]
    assert {(r.status_code, r.json()["detail"]) for r in responses} == {(400, "invalid_link_code")}
    reasons = [reason for outcome, reason in harness.audit("channel_links.confirm")]
    assert [reason.split()[-1] for reason in reasons[1:]] == [
        "code_foreign",
        "code_expired",
        "code_used",
        "code_unknown",
    ]
    # Использованный код не дал второму аккаунту захватить привязку.
    assert harness.sql("SELECT count(*) FROM external_identities WHERE source = 'channel'") == [
        (1,)
    ]


def test_account_linked_to_another_principal_is_not_taken_over(harness: Harness, linked) -> None:
    intruder = harness.mint(harness.principal())
    code = harness.intent(intruder).json()["code"]
    response = harness.confirm(linked["adapter"], code)
    assert response.status_code == 409
    assert response.json()["detail"] == "channel_account_linked"
    assert harness.exchange(linked["adapter"]).json()["principalId"] == linked["principal"]


def test_intent_requires_fresh_human_authentication(harness: Harness) -> None:
    harness.tenant()
    harness.provider()
    stale = harness.mint(harness.principal(), auth_time=datetime.now(UTC) - timedelta(seconds=301))
    response = harness.intent(stale)
    assert response.status_code == 403
    assert response.json()["detail"] == "authentication_context_expired"


def test_channel_derived_token_cannot_open_a_new_link(harness: Harness) -> None:
    harness.tenant()
    harness.provider()
    token = harness.mint(harness.principal(), acr="channel:telegram")
    response = harness.intent(token)
    assert response.status_code == 403
    assert response.json()["detail"] == "channel_authentication_not_allowed"


# --- провайдер и привязка --------------------------------------------------


def test_disabled_provider_closes_every_step(harness: Harness, linked) -> None:
    harness.provider("disabled")
    adapter = linked["adapter"]
    fresh = harness.mint(harness.principal())

    assert harness.intent(fresh).json()["detail"] == "channel_provider_disabled"
    assert harness.confirm(adapter, "any-code").json()["detail"] == "channel_provider_disabled"
    response = harness.exchange(adapter)
    assert response.status_code == 403
    assert response.json()["detail"] == "channel_provider_disabled"

    # Привязка пережила выключение и снова работает после включения.
    harness.provider("active")
    assert harness.exchange(adapter).status_code == 200


def test_provider_is_off_until_enabled_per_tenant(harness: Harness) -> None:
    harness.tenant()
    response = harness.intent(harness.mint(harness.principal()))
    assert response.status_code == 403
    assert response.json()["detail"] == "channel_provider_disabled"


def test_unlinked_and_revoked_accounts_cannot_exchange(harness: Harness, linked) -> None:
    adapter, human = linked["adapter"], linked["human"]
    unknown = harness.exchange(adapter, subject="999")
    assert unknown.status_code == 404
    assert unknown.json()["detail"] == "channel_account_not_linked"

    link_id = linked["link"]["linkId"]
    # Чужую привязку не отозвать: она неотличима от несуществующей.
    stranger = harness.mint(harness.principal())
    foreign = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/channel-links/{link_id}:revoke", headers=stranger
    )
    assert foreign.status_code == 404
    assert harness.exchange(adapter).status_code == 200

    harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/channel-links/{link_id}:revoke", headers=human
    )
    response = harness.exchange(adapter)
    assert response.status_code == 404
    assert response.json()["detail"] == "channel_account_not_linked"
    assert ("denied", "channel:telegram purpose:approval:42 channel_account_not_linked") in (
        harness.audit("channel_assertions.exchange")
    )


def test_disabled_principal_cannot_exchange(harness: Harness, linked) -> None:
    harness.sql(
        "UPDATE principals SET status = 'disabled' WHERE id = ?",
        uuid.UUID(linked["principal"]).hex,
    )
    response = harness.exchange(linked["adapter"])
    assert response.status_code == 403
    assert response.json()["detail"] == "principal_not_active"


def test_decide_scope_must_be_allowed_by_audience(harness: Harness) -> None:
    harness.tenant(decide_scope=False)
    harness.provider()
    adapter, _ = harness.adapter()
    harness.link(harness.mint(harness.principal()), adapter)
    response = harness.exchange(adapter)
    assert response.status_code == 403
    assert response.json()["detail"] == "scope_not_allowed"


# --- principal-агент и чужие предъявители ----------------------------------


def test_agent_principal_cannot_link_or_decide(harness: Harness) -> None:
    tenant_id = harness.tenant()
    harness.provider()
    agent_id = harness.principal("agent")

    response = harness.intent(harness.mint(agent_id, principal_type="agent"))
    assert response.status_code == 403
    assert response.json()["detail"] == "human_principal_required"

    # Даже если привязка к агенту как-то появилась, token человека по ней не выйдет.
    harness.sql(
        "INSERT INTO external_identities (id, principal_id, issuer, subject, external_id, "
        "source, status, created_at) VALUES (?, ?, ?, ?, ?, 'channel', 'active', ?)",
        uuid.uuid4().hex,
        uuid.UUID(agent_id).hex,
        channel_issuer(uuid.UUID(tenant_id), "telegram"),
        TELEGRAM_USER,
        TELEGRAM_USER,
        sqlite_time(datetime.now(UTC)),
    )
    adapter, _ = harness.adapter()
    response = harness.exchange(adapter)
    assert response.status_code == 422
    assert response.json()["detail"] == "human_principal_required"


def test_only_the_scoped_adapter_of_the_same_tenant_may_confirm_and_exchange(
    harness: Harness, linked
) -> None:
    tenant_id = harness.tenant_id
    # Человек не может сам себе выписать assertion канала.
    response = harness.exchange(linked["human"])
    assert response.status_code == 403
    assert response.json()["detail"] == "service_account_required"

    unscoped, _ = harness.adapter(scopes=[])
    assert harness.exchange(unscoped).json()["detail"] == "scope_not_granted"

    other_tenant = harness.tenant("tenant-b")
    foreign_adapter, _ = harness.adapter(tenant_id=other_tenant)
    response = harness.exchange(foreign_adapter, tenant_id=tenant_id)
    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_mismatch"

    # Отозванный service account закрывается сразу, не дожидаясь срока token.
    adapter, client_id = harness.adapter()
    assert harness.exchange(adapter).status_code == 200
    harness.client.post(
        f"/api/v1/tenants/{tenant_id}/service-accounts/{client_id}:revoke", headers=BOOTSTRAP
    )
    assert harness.exchange(adapter).status_code == 401
    assert harness.exchange({"Authorization": "Bearer nope"}).status_code == 401


# --- лимиты частоты --------------------------------------------------------


def test_rate_limits(tmp_path) -> None:
    client, harness = build_harness(
        tmp_path,
        channel_link_intent_limit=2,
        channel_confirm_failure_limit=2,
        channel_assertion_limit=2,
    )
    with client:
        harness.tenant()
        harness.provider()
        human = harness.mint(harness.principal())
        adapter, _ = harness.adapter()

        assert harness.intent(human).status_code == 201
        assert harness.intent(human).status_code == 201
        limited = harness.intent(human)
        assert limited.status_code == 429
        assert limited.headers["Retry-After"] == "600"

        # Перебор кодов: после двух отказов адаптер упирается в лимит даже с
        # верным кодом.
        second = harness.mint(harness.principal())
        code = harness.intent(second).json()["code"]
        assert harness.confirm(adapter, "wrong-1").status_code == 400
        assert harness.confirm(adapter, "wrong-2").status_code == 400
        assert harness.confirm(adapter, code).status_code == 429

        fresh_adapter, _ = harness.adapter()
        assert harness.confirm(fresh_adapter, code).status_code == 200
        assert harness.exchange(fresh_adapter).status_code == 200
        assert harness.exchange(fresh_adapter).status_code == 200
        response = harness.exchange(fresh_adapter)
        assert response.status_code == 429
        assert response.json()["detail"] == "rate_limited"
