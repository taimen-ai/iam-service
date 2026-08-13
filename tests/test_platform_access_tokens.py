"""Platform Access Token и обмен на audience-bound credential (IAM-3).

Тесты работают на изолированной sqlite-базе и не поднимают Keycloak: human
authentication context регистрируется тем же контрактом, который вызывает
federation-вход. Проверяется весь negative matrix: хранение секрета, отзыв,
истечение, отключение Principal, потолок scope, чужой audience, ротация,
replay и ambiguous response.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from iam_service.app import create_app
from iam_service.config import Settings
from iam_service.pat.models import AuthenticationContext, PlatformAccessToken
from iam_service.tokens import verify_access_token

BOOTSTRAP = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}
ISSUER = "https://iam.example"
AUDIENCE_SCOPES = {"control-plane": ["read"], "memory-service": ["read", "write"]}


class Harness:
    """Поднятый сервис плюс прямой доступ к базе для подготовки состояния."""

    def __init__(self, client: TestClient, database_path, public_pem: str) -> None:
        self.client = client
        self.database_path = database_path
        self.public_pem = public_pem
        self.engine = create_engine(f"sqlite:///{database_path}")
        self.tenant_id = ""

    def session(self) -> Session:
        return Session(self.engine)

    def create_tenant(self, slug: str = "tenant-a") -> str:
        tenant = self.client.post(
            "/api/v1/tenants", headers=BOOTSTRAP, json={"slug": slug, "name": "A"}
        ).json()
        self.tenant_id = tenant["id"]
        for key, scopes in AUDIENCE_SCOPES.items():
            response = self.client.post(
                f"/api/v1/tenants/{self.tenant_id}/audiences",
                headers=BOOTSTRAP,
                json={"key": key, "allowedScopes": scopes},
            )
            assert response.status_code == 201, response.text
        return self.tenant_id

    def create_principal(self, kind: str = "human", name: str = "Operator") -> str:
        response = self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/principals",
            headers=BOOTSTRAP,
            json={"kind": kind, "displayName": name},
        )
        assert response.status_code == 201, response.text
        return response.json()["id"]

    def authenticate(self, principal_id: str, *, age_seconds: int = 0):
        """Зарегистрировать подтверждённый human-вход.

        `age_seconds` состаривает запись напрямую в базе: свежесть считается
        по серверному `recorded_at`, подделать её через тело запроса нельзя.
        """

        response = self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/principals/{principal_id}/authentication-contexts",
            headers=BOOTSTRAP,
            json={
                "issuer": "https://idp.example/realms/platform",
                "acr": "urn:mace:incommon:iap:silver",
                "amr": ["pwd", "otp"],
            },
        )
        if response.status_code == 201 and age_seconds:
            with self.session() as session:
                context = session.get(AuthenticationContext, uuid.UUID(response.json()["id"]))
                context.recorded_at = datetime.now(UTC) - timedelta(seconds=age_seconds)
                session.commit()
        return response

    def issue(
        self,
        principal_id: str,
        *,
        audiences: list[str] | None = None,
        scope_ceiling: list[str] | None = None,
        idempotency_key: str | None = None,
        **extra,
    ):
        payload = {
            "name": "codex-cli",
            "audiences": audiences if audiences is not None else ["control-plane"],
            "scopeCeiling": scope_ceiling if scope_ceiling is not None else ["read"],
            **extra,
        }
        return self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/principals/{principal_id}/platform-access-tokens",
            headers={**BOOTSTRAP, "Idempotency-Key": idempotency_key or str(uuid.uuid4())},
            json=payload,
        )

    def exchange(self, token: str, audience: str, scopes: list[str] | None = None):
        return self.client.post(
            "/api/v1/platform-access-tokens:exchange",
            json={"token": token, "audience": audience, "scopes": scopes or []},
        )

    def claims(self, access_token: str, audience: str) -> dict:
        return verify_access_token(
            access_token, public_key=self.public_pem, issuer=ISSUER, audience=audience
        )

    def dump(self) -> str:
        """Всё содержимое базы одной строкой — для проверки отсутствия секрета."""

        with sqlite3.connect(self.database_path) as connection:
            tables = [
                row[0]
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            ]
            return "\n".join(
                f"{table}:{list(connection.execute(f'SELECT * FROM {table}'))}" for table in tables
            )


def signing_key_pair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


@pytest.fixture
def harness(tmp_path):
    private_pem, public_pem = signing_key_pair()
    database_path = tmp_path / "iam.db"
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{database_path}",
        bootstrap_token="test-bootstrap-token",
        issuer=ISSUER,
        signing_private_key=private_pem,
        create_schema_on_startup=True,
    )
    with TestClient(create_app(settings)) as client:
        harness = Harness(client, database_path, public_pem)
        harness.create_tenant()
        yield harness


def ready_principal(harness: Harness) -> str:
    principal_id = harness.create_principal()
    harness.authenticate(principal_id)
    return principal_id


def test_full_token_is_never_stored_and_never_shown_twice(harness: Harness) -> None:
    principal_id = ready_principal(harness)
    key = str(uuid.uuid4())

    first = harness.issue(principal_id, idempotency_key=key)
    assert first.status_code == 201, first.text
    token = first.json()["token"]
    assert token.startswith("iam_pat_")

    replay = harness.issue(principal_id, idempotency_key=key)

    assert replay.status_code == 201
    assert replay.headers.get("idempotency-replayed") == "true"
    # Ambiguous response не выпускает второй credential и не повторяет секрет.
    assert replay.json()["token"] is None
    assert replay.json()["credential"]["id"] == first.json()["credential"]["id"]

    dump = harness.dump()
    assert token not in dump
    assert token.rsplit("_", 1)[1] not in dump
    assert hashlib.sha256(token.encode()).hexdigest() in dump
    with harness.session() as session:
        assert len(list(session.scalars(select(PlatformAccessToken)))) == 1


def test_issuance_requires_fresh_human_authentication_context(harness: Harness) -> None:
    never_authenticated = harness.create_principal()
    stale = harness.create_principal(name="Stale operator")
    harness.authenticate(stale, age_seconds=3600)
    agent = harness.create_principal(kind="agent", name="Agent")

    assert harness.issue(never_authenticated).status_code == 403
    assert harness.issue(never_authenticated).json()["detail"] == "authentication_context_required"
    assert harness.issue(stale).json()["detail"] == "authentication_context_expired"
    # PAT принадлежит человеку: service account'ы ходят по client credentials.
    assert harness.issue(agent).json()["detail"] == "human_principal_required"
    assert harness.authenticate(agent).status_code == 422


def test_token_is_bound_to_one_audience_and_ceiling_only_narrows(harness: Harness) -> None:
    principal_id = ready_principal(harness)
    token = harness.issue(
        principal_id,
        audiences=["control-plane", "memory-service"],
        scope_ceiling=["read", "write"],
    ).json()["token"]

    default_scopes = harness.exchange(token, "control-plane")
    escalation = harness.exchange(token, "control-plane", ["write"])
    memory = harness.exchange(token, "memory-service", ["write"])

    assert default_scopes.status_code == 200
    # Потолок шире, чем разрешает audience, — эффективные scopes сужаются.
    assert default_scopes.json()["scope"] == ["read"]
    assert escalation.status_code == 403
    assert escalation.json()["detail"] == "scope_not_allowed"
    assert memory.status_code == 200
    assert memory.json()["scope"] == ["write"]

    claims = harness.claims(default_scopes.json()["accessToken"], "control-plane")
    assert claims["scope"] == ["read"]
    assert claims["scope_ceiling"] == ["read", "write"]
    assert claims["principal_type"] == "human"
    assert claims["acr"] == "urn:mace:incommon:iap:silver"
    assert claims["session_id"] == default_scopes.json()["sessionId"]
    # Ни entitlement, ни доменных прав в token нет — их выдают другие сервисы.
    assert set(claims) == {
        "iss",
        "sub",
        "tenant_id",
        "aud",
        "scope",
        "scope_ceiling",
        "principal_type",
        "credential_id",
        "session_id",
        "auth_time",
        "acr",
        "iat",
        "nbf",
        "exp",
        "jti",
    }
    with pytest.raises(jwt.InvalidAudienceError):
        harness.claims(default_scopes.json()["accessToken"], "memory-service")


def test_audience_outside_credential_is_refused(harness: Harness) -> None:
    principal_id = ready_principal(harness)
    token = harness.issue(principal_id, audiences=["control-plane"]).json()["token"]

    response = harness.exchange(token, "memory-service")

    assert response.status_code == 403
    assert response.json()["detail"] == "audience_not_allowed"


def test_revoked_expired_and_disabled_principal_get_no_credential(harness: Harness) -> None:
    principal_id = ready_principal(harness)
    revoked = harness.issue(principal_id).json()
    expired = harness.issue(principal_id).json()
    disabled = harness.issue(principal_id).json()

    revoke = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}"
        f"/platform-access-tokens/{revoked['credential']['id']}:revoke",
        headers=BOOTSTRAP,
    )
    assert revoke.status_code == 204
    with harness.session() as session:
        credential = session.get(PlatformAccessToken, uuid.UUID(expired["credential"]["id"]))
        credential.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()

    after_revoke = harness.exchange(revoked["token"], "control-plane")
    after_expiry = harness.exchange(expired["token"], "control-plane")
    disable = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{principal_id}:disable",
        headers=BOOTSTRAP,
    )
    after_disable = harness.exchange(disabled["token"], "control-plane")
    reissue = harness.issue(principal_id)

    assert after_revoke.status_code == 401
    assert after_expiry.status_code == 401
    # Причина отказа не раскрывается клиенту, чтобы endpoint не был оракулом.
    assert after_revoke.json()["detail"] == after_expiry.json()["detail"] == "invalid_token"
    assert disable.status_code == 200
    # Отзываются все ещё не отозванные credentials, включая просроченный.
    assert disable.json()["revokedCredentials"] == 2
    assert after_disable.status_code == 401
    # Отключённый Principal не получает и новых credentials.
    assert reissue.status_code == 409


def test_rotation_replaces_secret_without_extending_authority(harness: Harness) -> None:
    principal_id = ready_principal(harness)
    original = harness.issue(
        principal_id, audiences=["control-plane"], scope_ceiling=["read"]
    ).json()

    rotated = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}"
        f"/platform-access-tokens/{original['credential']['id']}:rotate",
        headers={**BOOTSTRAP, "Idempotency-Key": str(uuid.uuid4())},
        json={},
    )

    assert rotated.status_code == 201, rotated.text
    successor = rotated.json()
    assert successor["token"] != original["token"]
    assert successor["credential"]["rotatedFromId"] == original["credential"]["id"]
    # Ротация не продлевает окно и не расширяет authority.
    assert successor["credential"]["expiresAt"] == original["credential"]["expiresAt"]
    assert successor["credential"]["scopeCeiling"] == original["credential"]["scopeCeiling"]
    assert successor["credential"]["audiences"] == original["credential"]["audiences"]
    assert harness.exchange(original["token"], "control-plane").status_code == 401
    assert harness.exchange(successor["token"], "control-plane").status_code == 200


def test_issued_access_token_cannot_be_replayed_as_credential(harness: Harness) -> None:
    principal_id = ready_principal(harness)
    token = harness.issue(principal_id).json()["token"]

    first = harness.exchange(token, "control-plane").json()
    second = harness.exchange(token, "control-plane").json()
    replay = harness.exchange(first["accessToken"], "control-plane")
    forged = harness.exchange("iam_pat_" + "0" * 12 + "_forged-secret", "control-plane")

    # Каждый обмен — самостоятельный credential с собственными jti и session.
    assert first["accessToken"] != second["accessToken"]
    assert first["sessionId"] != second["sessionId"]
    claims = harness.claims(first["accessToken"], "control-plane")
    assert claims["jti"] != harness.claims(second["accessToken"], "control-plane")["jti"]
    # Выданный access token не является credential и не принимается обратно.
    assert replay.status_code == 401
    assert forged.status_code == 401


def test_legacy_control_plane_api_key_works_through_compatibility_mapping(
    harness: Harness,
) -> None:
    principal_id = harness.create_principal(kind="agent", name="Legacy worker")
    # Ключ выпущен Control Plane; IAM получает только prefix и hash.
    prefix = secrets.token_hex(6)
    legacy_key = f"cp_{prefix}_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(legacy_key.encode()).hexdigest()
    payload = {
        "principalId": principal_id,
        "name": "control-plane migration key",
        "keyPrefix": prefix,
        "keyHash": key_hash,
        "audience": "control-plane",
        "scopeCeiling": ["read"],
        "expiresInSeconds": 604800,
    }

    imported = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/legacy-credentials:import",
        headers=BOOTSTRAP,
        json=payload,
    )
    exchanged = harness.exchange(legacy_key, "control-plane")
    endless = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/legacy-credentials:import",
        headers=BOOTSTRAP,
        json={**payload, "keyPrefix": secrets.token_hex(6), "expiresInSeconds": 31536000},
    )
    with_plaintext = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/legacy-credentials:import",
        headers=BOOTSTRAP,
        json={**payload, "key": legacy_key},
    )

    assert imported.status_code == 201, imported.text
    assert imported.json()["kind"] == "legacy_control_plane_api_key"
    assert exchanged.status_code == 200
    assert harness.claims(exchanged.json()["accessToken"], "control-plane")["scope"] == ["read"]
    # Окно совместимости ограничено, а открытый ключ вообще не принимается.
    assert endless.status_code == 422
    assert endless.json()["detail"] == "compatibility_window_too_long"
    assert with_plaintext.status_code == 422
    assert legacy_key not in harness.dump()


def test_federation_login_alone_unlocks_issuance(tmp_path, idp, fetcher) -> None:
    """Вход через IdP открывает выпуск PAT без административного вмешательства.

    Federation пишет снимок аутентификации в той же транзакции, что и linking,
    поэтому отдельный вызов `authentication-contexts` не нужен.
    """

    private_pem, public_pem = signing_key_pair()
    database_path = tmp_path / "iam.db"
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{database_path}",
        bootstrap_token="test-bootstrap-token",
        issuer=ISSUER,
        signing_private_key=private_pem,
        create_schema_on_startup=True,
    )

    with TestClient(create_app(settings, jwks_fetcher=fetcher)) as client:
        tenant_id = client.post(
            "/api/v1/tenants", headers=BOOTSTRAP, json={"slug": "tenant-a", "name": "A"}
        ).json()["id"]
        client.post(
            f"/api/v1/tenants/{tenant_id}/audiences",
            headers=BOOTSTRAP,
            json={"key": "control-plane", "allowedScopes": ["read"]},
        )
        client.post(
            f"/api/v1/tenants/{tenant_id}/identity-providers",
            headers=BOOTSTRAP,
            json={"key": "keycloak", "issuer": idp.issuer, "audience": idp.audience},
        )
        login = client.post(
            f"/api/v1/tenants/{tenant_id}/federation:authenticate",
            json={
                "identityProvider": "keycloak",
                "token": idp.token(claims={"acr": "silver", "amr": ["pwd", "otp"]}),
            },
        )
        principal_id = login.json()["principalId"]
        issued = client.post(
            f"/api/v1/tenants/{tenant_id}/principals/{principal_id}/platform-access-tokens",
            headers={**BOOTSTRAP, "Idempotency-Key": str(uuid.uuid4())},
            json={"name": "claude-code", "audiences": ["control-plane"], "scopeCeiling": ["read"]},
        )
        exchanged = client.post(
            "/api/v1/platform-access-tokens:exchange",
            json={"token": issued.json()["token"], "audience": "control-plane", "scopes": ["read"]},
        )

    assert login.status_code == 200, login.text
    assert issued.status_code == 201, issued.text
    assert exchanged.status_code == 200, exchanged.text
    claims = verify_access_token(
        exchanged.json()["accessToken"],
        public_key=public_pem,
        issuer=ISSUER,
        audience="control-plane",
    )
    # Контекст upstream-входа доезжает до выданного токена.
    assert claims["acr"] == "silver"

    with Session(create_engine(f"sqlite:///{database_path}")) as session:
        context = session.scalars(select(AuthenticationContext)).one()
    assert context.source == "federation"
    assert context.amr == ["otp", "pwd"]
    assert context.external_identity_id is not None


def test_migration_creates_and_drops_credential_tables(tmp_path) -> None:
    database_path = tmp_path / "migration.db"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{database_path}")
    added = {"authentication_contexts", "platform_access_tokens"}

    def tables() -> set[str]:
        with sqlite3.connect(database_path) as connection:
            return {
                row[0]
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }

    # Одна голова alembic: ветка IAM-3 продолжает цепочку, а не создаёт вторую.
    assert len(ScriptDirectory.from_config(config).get_heads()) == 1
    command.upgrade(config, "head")
    assert added <= tables()
    command.downgrade(config, "base")
    assert not added & tables()
    command.upgrade(config, "head")
    assert added <= tables()


def test_audit_records_prefix_and_never_the_secret(harness: Harness) -> None:
    principal_id = ready_principal(harness)
    issued = harness.issue(principal_id).json()
    harness.exchange(issued["token"], "control-plane")
    harness.exchange(issued["token"], "memory-service")

    events = harness.client.get("/api/v1/events", headers=BOOTSTRAP).text
    prefix = issued["credential"]["publicPrefix"]
    with sqlite3.connect(harness.database_path) as connection:
        audit = list(connection.execute("SELECT action, actor_ref, reason FROM audit_events"))

    actions = {row[0] for row in audit}
    assert "platform_access_tokens.issue" in actions
    assert "platform_access_tokens.exchange" in actions
    assert any(f"pat:{prefix}" in row[2] for row in audit)
    assert any(row[1] == principal_id for row in audit)
    # Отказ по audience тоже фиксируется, но без секрета.
    assert any("audience:memory-service" in row[2] for row in audit)
    assert issued["token"] not in str(audit)
    assert issued["token"] not in events
    assert prefix in events
