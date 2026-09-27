"""Агенты владельца: service account со scope `iam:agents` (declarative-agents D003).

Приёмка: service account без bootstrap-токена заводит агента и выпускает ему
PAT, а чужого агента не трогает. Negative matrix: чужой агент — 403, human —
422, отзыв закрывает обмен, предъявитель без scope, отозванный service
account, чужой tenant, authority шире владельца.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from iam_service.app import create_app
from iam_service.config import Settings
from iam_service.tokens import TokenIssuer, verify_access_token

BOOTSTRAP = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}
ISSUER = "https://iam.example"
AUDIENCE_SCOPES = {
    "iam": ["iam:agents", "iam:channel-links"],
    "control-plane": ["control-plane:read", "control-plane:write"],
    "memory-service": ["memory:read"],
}


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

    # --- подготовка (единственное место, где нужен bootstrap) -----------

    def tenant(self, slug: str = "tenant-a") -> str:
        tenant_id = self.client.post(
            "/api/v1/tenants", headers=BOOTSTRAP, json={"slug": slug, "name": slug}
        ).json()["id"]
        for key, scopes in AUDIENCE_SCOPES.items():
            response = self.client.post(
                f"/api/v1/tenants/{tenant_id}/audiences",
                headers=BOOTSTRAP,
                json={"key": key, "allowedScopes": scopes},
            )
            assert response.status_code == 201, response.text
        self.tenant_id = self.tenant_id or tenant_id
        return tenant_id

    def service_account(
        self,
        *,
        tenant_id: str | None = None,
        audiences: list[str] | None = None,
        ceiling: list[str] | None = None,
    ) -> dict[str, str]:
        response = self.client.post(
            f"/api/v1/tenants/{tenant_id or self.tenant_id}/service-accounts",
            headers=BOOTSTRAP,
            json={
                "displayName": "agent controller",
                "audiences": audiences or ["iam", "control-plane"],
                "scopeCeiling": ceiling or ["iam:agents", "control-plane:read"],
            },
        )
        assert response.status_code == 201, response.text
        return response.json()

    def bearer(self, account: dict[str, str], scopes: list[str] | None = None) -> dict[str, str]:
        response = self.client.post(
            "/api/v1/tokens/exchange",
            json={
                "clientId": account["clientId"],
                "clientSecret": account["clientSecret"],
                "audience": "iam",
                "scopes": ["iam:agents"] if scopes is None else scopes,
            },
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['accessToken']}"}

    def controller(self, **kwargs) -> tuple[dict[str, str], dict[str, str]]:
        account = self.service_account(**kwargs)
        return self.bearer(account), account

    def principal(self, kind: str) -> str:
        response = self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/principals",
            headers=BOOTSTRAP,
            json={"kind": kind, "displayName": f"{kind} principal"},
        )
        assert response.status_code == 201, response.text
        return response.json()["id"]

    # --- путь владельца -------------------------------------------------

    def create_agent(self, headers: dict[str, str], *, tenant_id: str | None = None):
        return self.client.post(
            f"/api/v1/tenants/{tenant_id or self.tenant_id}/agents",
            headers=headers,
            json={"displayName": "coding runner"},
        )

    def issue(
        self,
        headers: dict[str, str],
        agent_id: str,
        *,
        idempotency_key: str | None = None,
        audiences: list[str] | None = None,
        ceiling: list[str] | None = None,
        expires_in: int | None = 3600,
    ):
        body: dict = {
            "name": "runner",
            "audiences": audiences or ["control-plane"],
            "scopeCeiling": ["control-plane:read"] if ceiling is None else ceiling,
        }
        if expires_in is not None:
            body["expiresInSeconds"] = expires_in
        return self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/agents/{agent_id}/platform-access-tokens",
            headers={
                **headers,
                "Idempotency-Key": idempotency_key or str(uuid.uuid4()),
            },
            json=body,
        )

    def revoke(self, headers: dict[str, str], agent_id: str, credential_id: str):
        return self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/agents/{agent_id}"
            f"/platform-access-tokens/{credential_id}:revoke",
            headers=headers,
        )

    def exchange(self, token: str, audience: str = "control-plane"):
        return self.client.post(
            "/api/v1/platform-access-tokens:exchange",
            json={"token": token, "audience": audience, "scopes": []},
        )

    def audit(self, action: str) -> list[tuple[str, str, str]]:
        with sqlite3.connect(self.database_path) as connection:
            return list(
                connection.execute(
                    "SELECT actor_ref, outcome, reason FROM audit_events WHERE action = ?",
                    (action,),
                )
            )


@pytest.fixture
def harness(tmp_path):
    database_path = tmp_path / "iam.db"
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{database_path}",
        bootstrap_token="test-bootstrap-token",
        issuer=ISSUER,
        signing_private_key=signing_key_pem(),
        create_schema_on_startup=True,
    )
    with TestClient(create_app(settings)) as client:
        harness = Harness(client, database_path, settings)
        harness.tenant()
        yield harness


def test_service_account_creates_agent_and_issues_pat_without_bootstrap(harness: Harness) -> None:
    headers, account = harness.controller()

    created = harness.create_agent(headers)
    assert created.status_code == 201, created.text
    agent = created.json()
    assert agent["kind"] == "agent"
    assert agent["ownerPrincipalId"] == account["principalId"]
    # Владелец виден и в обычном представлении principal.
    view = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{agent['id']}", headers=BOOTSTRAP
    ).json()
    assert view["owner_principal_id"] == account["principalId"]

    key = str(uuid.uuid4())
    issued = harness.issue(headers, agent["id"], idempotency_key=key, expires_in=3600)
    assert issued.status_code == 201, issued.text
    token = issued.json()["token"]
    credential = issued.json()["credential"]
    assert token.startswith("iam_pat_")
    assert credential["principalId"] == agent["id"]
    expires_at = datetime.fromisoformat(credential["expiresAt"]).replace(tzinfo=UTC)
    assert 3500 < (expires_at - datetime.now(UTC)).total_seconds() <= 3600

    # Ambiguous response: тот же credential, секрет второй раз не показывается.
    replay = harness.issue(headers, agent["id"], idempotency_key=key)
    assert replay.status_code == 201
    assert replay.headers.get("idempotency-replayed") == "true"
    assert replay.json()["token"] is None
    assert replay.json()["credential"]["id"] == credential["id"]

    exchanged = harness.exchange(token)
    assert exchanged.status_code == 200, exchanged.text
    claims = verify_access_token(
        exchanged.json()["accessToken"],
        public_key=TokenIssuer(
            issuer=ISSUER,
            private_key=harness.settings.signing_private_key,
            key_id=harness.settings.signing_key_id,
            ttl_seconds=300,
        ).private_key.public_key(),
        issuer=ISSUER,
        audience="control-plane",
    )
    assert claims["sub"] == agent["id"]
    assert claims["principal_type"] == "agent"
    assert claims["scope"] == ["control-plane:read"]
    # Человеческого входа у агента нет и в token он не имитируется.
    assert "auth_time" not in claims and "acr" not in claims

    assert [row[:2] for row in harness.audit("agents.create")] == [
        (account["principalId"], "allowed")
    ]
    issue_audit = harness.audit("platform_access_tokens.issue")
    assert issue_audit[0][0] == account["principalId"]
    assert token not in str(issue_audit)


def test_foreign_agent_is_refused_with_403(harness: Harness) -> None:
    owner, _ = harness.controller()
    stranger, stranger_account = harness.controller()
    agent = harness.create_agent(owner).json()["id"]
    credential = harness.issue(owner, agent).json()["credential"]["id"]

    issued = harness.issue(stranger, agent)
    assert issued.status_code == 403
    assert issued.json()["detail"] == "agent_not_owned"
    revoked = harness.revoke(stranger, agent, credential)
    assert revoked.status_code == 403
    assert revoked.json()["detail"] == "agent_not_owned"

    # Агент, заведённый bootstrap-операцией, владельца не имеет — и тоже чужой.
    unowned = harness.principal("agent")
    assert harness.issue(owner, unowned).status_code == 403

    denied = harness.audit("agents.platform_access_tokens.issue")
    assert (stranger_account["principalId"], "denied") in [row[:2] for row in denied]
    assert harness.audit("agents.platform_access_tokens.revoke")[0][1] == "denied"


def test_human_and_service_account_principals_are_refused_with_422(harness: Harness) -> None:
    headers, account = harness.controller()

    for kind in ("human", "service_account"):
        target = harness.principal(kind)
        response = harness.issue(headers, target)
        assert response.status_code == 422, kind
        assert response.json()["detail"] == "agent_principal_required"
    # Сам себе владелец тоже не выпускает PAT: он не агент.
    assert harness.issue(headers, account["principalId"]).status_code == 422
    assert harness.issue(headers, str(uuid.uuid4())).status_code == 404


def test_revocation_kills_exchange(harness: Harness) -> None:
    headers, _ = harness.controller()
    agent = harness.create_agent(headers).json()["id"]
    issued = harness.issue(headers, agent).json()
    token, credential = issued["token"], issued["credential"]["id"]
    assert harness.exchange(token).status_code == 200

    assert harness.revoke(headers, agent, credential).status_code == 204
    # Повторный отзыв идемпотентен.
    assert harness.revoke(headers, agent, credential).status_code == 204

    refused = harness.exchange(token)
    assert refused.status_code == 401
    assert refused.json()["detail"] == "invalid_token"
    # Credential другого агента того же владельца через этот путь не находится.
    other = harness.create_agent(headers).json()["id"]
    assert harness.revoke(headers, other, credential).status_code == 404


def test_caller_must_be_active_service_account_with_agents_scope(harness: Harness) -> None:
    path = f"/api/v1/tenants/{harness.tenant_id}/agents"
    body = {"displayName": "x"}

    assert harness.client.post(path, json=body).status_code == 401
    # Bootstrap-токен этот путь не открывает.
    assert harness.client.post(path, headers=BOOTSTRAP, json=body).status_code == 401

    account = harness.service_account()
    without_scope = harness.bearer(account, scopes=[])
    response = harness.create_agent(without_scope)
    assert response.status_code == 403
    assert response.json()["detail"] == "scope_not_granted"

    # Token человека (или агента) с тем же scope — не service account.
    human = harness.principal("human")
    token = TokenIssuer(
        issuer=ISSUER,
        private_key=harness.settings.signing_private_key,
        key_id=harness.settings.signing_key_id,
        ttl_seconds=300,
    ).issue(
        subject=uuid.UUID(human),
        tenant_id=uuid.UUID(harness.tenant_id),
        audience="iam",
        scopes=["iam:agents"],
        credential_id=uuid.uuid4(),
        principal_type="human",
    )
    response = harness.create_agent({"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert response.json()["detail"] == "service_account_required"

    # Отзыв service account действует сразу, не дожидаясь истечения его token.
    headers = harness.bearer(account)
    assert harness.create_agent(headers).status_code == 201
    revoked = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/service-accounts/{account['clientId']}:revoke",
        headers=BOOTSTRAP,
    )
    assert revoked.status_code == 204
    assert harness.create_agent(headers).status_code == 401

    # Tenant берётся из подписанного token, а не из пути.
    other_tenant = harness.tenant("tenant-b")
    foreign, _ = harness.controller(tenant_id=other_tenant)
    response = harness.create_agent(foreign)
    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_mismatch"


def test_agent_authority_never_exceeds_owner(harness: Harness) -> None:
    headers, _ = harness.controller()
    agent = harness.create_agent(headers).json()["id"]

    def detail(response) -> str:
        assert response.status_code == 422, response.text
        return response.json()["detail"]

    # Audience существует, но владелец его не держит.
    assert (
        detail(harness.issue(headers, agent, audiences=["memory-service"], ceiling=[]))
        == "audience_not_delegable"
    )
    # Scope разрешён audience, но не входит в потолок владельца.
    assert (
        detail(harness.issue(headers, agent, ceiling=["control-plane:write"]))
        == "scope_not_delegable"
    )
    # Право заводить агентов не делегируется.
    assert (
        detail(harness.issue(headers, agent, audiences=["iam"], ceiling=["iam:agents"]))
        == "scope_not_delegable"
    )
    assert detail(harness.issue(headers, agent, audiences=["billing"])) == "unknown_audience"
    assert detail(harness.issue(headers, agent, ceiling=["memory:read"])) == "invalid_scope_ceiling"
    # Срок обязателен и ограничен.
    assert harness.issue(headers, agent, expires_in=None).status_code == 422
    too_long = harness.settings.agent_pat_max_ttl_seconds + 1
    assert detail(harness.issue(headers, agent, expires_in=too_long)) == "expiry_too_long"
    assert harness.audit("agents.platform_access_tokens.issue")[0][1] == "denied"


def test_idempotency_key_is_required_and_bound_to_agent(harness: Harness) -> None:
    headers, _ = harness.controller()
    first = harness.create_agent(headers).json()["id"]
    second = harness.create_agent(headers).json()["id"]

    missing = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/agents/{first}/platform-access-tokens",
        headers=headers,
        json={"name": "r", "audiences": ["control-plane"], "expiresInSeconds": 600},
    )
    assert missing.status_code == 400
    assert missing.json()["detail"] == "idempotency_key_required"

    key = str(uuid.uuid4())
    assert harness.issue(headers, first, idempotency_key=key).status_code == 201
    reused = harness.issue(headers, second, idempotency_key=key)
    assert reused.status_code == 409
    assert reused.json()["detail"] == "idempotency_key_reused"


def test_disabled_agent_gets_no_new_credential(harness: Harness) -> None:
    headers, _ = harness.controller()
    agent = harness.create_agent(headers).json()["id"]
    issued = harness.issue(headers, agent).json()

    disabled = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{agent}:disable", headers=BOOTSTRAP
    )
    assert disabled.status_code == 200
    response = harness.issue(headers, agent)
    assert response.status_code == 409
    assert response.json()["detail"] == "principal_not_active"
    # Отзыв остаётся доступен владельцу и для отключённого агента.
    assert harness.revoke(headers, agent, issued["credential"]["id"]).status_code == 204


def test_migration_adds_and_drops_principal_owner(tmp_path) -> None:
    database_path = tmp_path / "migration.db"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{database_path}")

    def columns() -> set[str]:
        with sqlite3.connect(database_path) as connection:
            return {row[1] for row in connection.execute("PRAGMA table_info(principals)")}

    command.upgrade(config, "head")
    assert "owner_principal_id" in columns()
    command.downgrade(config, "0005_channel_login")
    assert "owner_principal_id" not in columns()
    command.upgrade(config, "head")
    assert "owner_principal_id" in columns()
