"""Управление людьми: человек со scope `iam:people` (runtime-console R003).

Приёмка: token человека из federation-входа со `iam:people` заводит human
Principal и external identity, без scope — 403, агентский token со scope —
403, audit называет вызывающего. Negative matrix: scope не выдаётся ни PAT,
ни client credentials, ни человеку вне группы `people-admins`, ни по пустому
запросу; token человека не из federation не проходит; агентов и service
account человек не трогает; привязка identity — только онбординг чужого
человека без способа входа (identity любого статуса, PAT) и не администратора;
группу администраторов federation не создаёт; себя и других администраторов не отключить;
отключение identity или выход из группы закрывают путь сразу. Bootstrap-путь
остаётся прежним. `:enable` (TASK-000907) возвращает вход через IdP, но не
отозванные credentials и не прежние сессии.
"""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from conftest import FakeFetcher, FakeIdentityProvider
from iam_service.app import create_app
from iam_service.config import Settings
from iam_service.tokens import TokenIssuer

BOOTSTRAP = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}
ISSUER = "https://iam.example"
# Upstream-группа IdP, которую провайдер проецирует в группу администраторов.
ADMIN_GROUP_UPSTREAM = "platform-people-admins"
AUDIENCE_SCOPES = {
    "iam": ["iam:agents", "iam:channel-links", "iam:people"],
    "control-plane": ["control-plane:read"],
}


def signing_key_pem() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


class Harness:
    def __init__(
        self, client: TestClient, database_path, settings: Settings, idp: FakeIdentityProvider
    ) -> None:
        self.client = client
        self.database_path = database_path
        self.settings = settings
        self.idp = idp
        self.tenant_id = ""
        self.admin_group_id = ""

    # --- подготовка (bootstrap) -----------------------------------------

    def tenant(self, slug: str = "tenant-a", *, admin_group: bool = True) -> str:
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
        provider = self.client.post(
            f"/api/v1/tenants/{tenant_id}/identity-providers",
            headers=BOOTSTRAP,
            json={
                "key": "keycloak",
                "issuer": self.idp.issuer,
                "audience": self.idp.audience,
                "lifecycleProfile": "managed",
                "groupMappings": {ADMIN_GROUP_UPSTREAM: "people-admins"},
            },
        )
        assert provider.status_code == 201, provider.text
        if admin_group:
            # Группу администраторов людей заводит только bootstrap: federation
            # лишь проецирует в неё членство.
            group = self.client.post(
                f"/api/v1/tenants/{tenant_id}/groups",
                headers=BOOTSTRAP,
                json={"key": "people-admins", "name": "People admins"},
            )
            assert group.status_code == 201, group.text
            self.admin_group_id = self.admin_group_id or group.json()["id"]
        self.tenant_id = self.tenant_id or tenant_id
        return tenant_id

    def bootstrap_principal(self, kind: str) -> str:
        response = self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/principals",
            headers=BOOTSTRAP,
            json={"kind": kind, "displayName": f"{kind} principal"},
        )
        assert response.status_code == 201, response.text
        return response.json()["id"]

    def issue_pat(self, human_id: str) -> dict[str, Any]:
        context = self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/principals/{human_id}/authentication-contexts",
            headers=BOOTSTRAP,
            json={"issuer": self.idp.issuer, "acr": "1", "amr": ["pwd"]},
        )
        assert context.status_code == 201, context.text
        issued = self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/principals/{human_id}/platform-access-tokens",
            headers={**BOOTSTRAP, "Idempotency-Key": str(uuid.uuid4())},
            json={"name": "cli", "audiences": ["iam"], "scopeCeiling": ["iam:people"]},
        )
        assert issued.status_code == 201, issued.text
        return issued.json()

    # --- вход человека --------------------------------------------------

    def exchange(self, *, subject: str, scopes: list[str], admin: bool):
        groups = [ADMIN_GROUP_UPSTREAM] if admin else []
        return self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/federation:exchange",
            json={
                "identityProvider": "keycloak",
                "token": self.idp.token(subject=subject, claims={"acr": "1", "groups": groups}),
                "audience": "iam",
                "scopes": scopes,
            },
        )

    def federate(
        self, *, subject: str = "admin", scopes: list[str] | None = None, admin: bool = True
    ) -> tuple[dict[str, str], dict[str, Any]]:
        response = self.exchange(
            subject=subject, scopes=["iam:people"] if scopes is None else scopes, admin=admin
        )
        assert response.status_code == 200, response.text
        body = response.json()
        return {"Authorization": f"Bearer {body['accessToken']}"}, body

    def forged(self, *, principal_id: str, principal_type: str, credential_id: str) -> dict:
        """Token, подписанный ключом IAM, — как если бы его выпустил иной путь."""

        token = TokenIssuer(
            issuer=ISSUER,
            private_key=self.settings.signing_private_key,
            key_id=self.settings.signing_key_id,
            ttl_seconds=300,
        ).issue(
            subject=uuid.UUID(principal_id),
            tenant_id=uuid.UUID(self.tenant_id),
            audience="iam",
            scopes=["iam:people"],
            credential_id=uuid.UUID(credential_id),
            principal_type=principal_type,
        )
        return {"Authorization": f"Bearer {token}"}

    # --- маршруты управления людьми -------------------------------------

    def create(
        self,
        headers: dict[str, str],
        *,
        kind: str = "human",
        name: str = "Second Person",
        idempotency_key: str | None = "",
    ):
        extra = {}
        if idempotency_key is not None:
            extra["Idempotency-Key"] = idempotency_key or str(uuid.uuid4())
        return self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/principals",
            headers={**headers, **extra},
            json={"kind": kind, "displayName": name},
        )

    def link(
        self,
        headers: dict[str, str],
        principal_id: str,
        subject: str = "second",
        issuer: str | None = None,
    ):
        return self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/principals/{principal_id}/external-identities",
            headers=headers,
            json={"issuer": issuer or self.idp.issuer, "subject": subject},
        )

    def disable(self, headers: dict[str, str], principal_id: str):
        return self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/principals/{principal_id}:disable",
            headers=headers,
        )

    def enable(self, headers: dict[str, str], principal_id: str, key: str | None = None):
        extra = {"Idempotency-Key": key} if key else {}
        return self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/principals/{principal_id}:enable",
            headers={**headers, **extra},
        )

    def audit(self, action: str) -> list[tuple[str, str, str]]:
        with sqlite3.connect(self.database_path) as connection:
            return list(
                connection.execute(
                    "SELECT actor_ref, outcome, reason FROM audit_events WHERE action = ? "
                    "ORDER BY rowid",
                    (action,),
                )
            )

    def denials(self, action: str) -> list[tuple[str, str, str]]:
        """(actor_ref, resource_type, reason) отказов действия."""

        with sqlite3.connect(self.database_path) as connection:
            return list(
                connection.execute(
                    "SELECT actor_ref, resource_type, reason FROM audit_events "
                    "WHERE action = ? AND outcome = 'denied' ORDER BY rowid",
                    (action,),
                )
            )

    def execute(self, sql: str, *params: Any) -> None:
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(sql, params)


@pytest.fixture
def harness(tmp_path, fetcher: FakeFetcher, idp: FakeIdentityProvider):
    database_path = tmp_path / "iam.db"
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{database_path}",
        bootstrap_token="test-bootstrap-token",
        issuer=ISSUER,
        signing_private_key=signing_key_pem(),
        create_schema_on_startup=True,
    )
    with TestClient(create_app(settings, jwks_fetcher=fetcher)) as client:
        harness = Harness(client, database_path, settings, idp)
        harness.tenant()
        yield harness


def test_people_scope_only_for_people_admins_and_only_on_request(harness: Harness) -> None:
    outsider = harness.exchange(subject="outsider", scopes=["iam:people"], admin=False)
    outsider_implicit = harness.exchange(subject="outsider", scopes=[], admin=False)
    admin_implicit = harness.exchange(subject="admin", scopes=[], admin=True)
    admin_explicit = harness.exchange(subject="admin", scopes=["iam:people"], admin=True)

    assert outsider.status_code == 403
    assert outsider.json()["detail"] == "scope_not_allowed"
    assert outsider_implicit.status_code == 200, outsider_implicit.text
    assert "iam:people" not in outsider_implicit.json()["scope"]
    # Пустой запрос не выдаёт `iam:people` даже администратору.
    assert admin_implicit.status_code == 200, admin_implicit.text
    assert "iam:people" not in admin_implicit.json()["scope"]
    assert admin_explicit.status_code == 200, admin_explicit.text
    assert admin_explicit.json()["scope"] == ["iam:people"]
    [denied] = [row for row in harness.audit("federation.exchange") if row[1] == "denied"]
    assert denied[0] == outsider_implicit.json()["principalId"]
    assert "group:people-admins" in denied[2]


def test_leaving_admin_group_closes_the_path_before_token_expiry(harness: Harness) -> None:
    headers, admin = harness.federate()
    harness.execute(
        "DELETE FROM group_members WHERE principal_id = ?",
        admin["principalId"].replace("-", ""),
    )

    response = harness.create(headers)

    assert response.status_code == 403
    assert response.json()["detail"] == "people_admin_required"
    assert harness.denials("people.authenticate") == [
        (admin["principalId"], "principal", "group:people-admins")
    ]


def test_human_with_people_scope_creates_human_and_external_identity(harness: Harness) -> None:
    headers, admin = harness.federate()
    assert admin["scope"] == ["iam:people"]
    admin_id = admin["principalId"]

    created = harness.create(headers, idempotency_key="add-second-person")
    assert created.status_code == 201, created.text
    person = created.json()
    assert person["kind"] == "human"
    assert person["display_name"] == "Second Person"

    linked = harness.link(headers, person["id"])
    assert linked.status_code == 201, linked.text
    assert linked.json()["principal_id"] == person["id"]

    view = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{person['id']}", headers=headers
    )
    assert view.status_code == 200, view.text
    listed = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals",
        headers=headers,
        params={"kind": "human"},
    )
    assert listed.status_code == 200, listed.text
    assert {item["id"] for item in listed.json()["items"]} == {admin_id, person["id"]}

    # Audit называет вызывающего человека, а не bootstrap.
    [create_audit] = harness.audit("principals.create")
    assert create_audit[0] == admin_id
    assert create_audit[1] == "allowed"
    assert "scope:iam:people" in create_audit[2]
    [link_audit] = harness.audit("external_identities.link")
    assert link_audit[:2] == (admin_id, "allowed")


def test_create_is_idempotent_by_key(harness: Harness) -> None:
    headers, admin = harness.federate()

    first = harness.create(headers, idempotency_key="same-key")
    replay = harness.create(headers, idempotency_key="same-key")
    other_body = harness.create(headers, idempotency_key="same-key", name="Someone Else")
    missing = harness.create(headers, idempotency_key=None)

    assert first.status_code == 201, first.text
    assert replay.status_code == 201, replay.text
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json()["id"] == first.json()["id"]
    assert other_body.status_code == 409
    assert other_body.json()["detail"] == "idempotency_key_reused"
    assert missing.status_code == 400
    assert missing.json()["detail"] == "idempotency_key_required"
    outcomes = [row[1] for row in harness.audit("principals.create")]
    assert outcomes == ["allowed", "denied"]
    assert harness.denials("principals.create") == [
        (admin["principalId"], "principal", "idempotency_key_reused")
    ]
    events = harness.client.get("/api/v1/events", headers=BOOTSTRAP).json()["items"]
    # Один principal.created — администратор из federation, второй — заведённый.
    assert [event["type"] for event in events].count("principal.created") == 2


def test_idempotency_key_belongs_to_the_caller(harness: Harness) -> None:
    first_headers, _ = harness.federate(subject="admin")
    second_headers, _ = harness.federate(subject="other-admin")

    mine = harness.create(first_headers, idempotency_key="shared-key")
    theirs = harness.create(second_headers, idempotency_key="shared-key", name="Someone Else")
    bootstrap = harness.create(BOOTSTRAP, idempotency_key="shared-key", name="Third")

    assert mine.status_code == 201, mine.text
    # Чужой ключ не открывает чужого Principal и не даёт 409.
    assert theirs.status_code == 201, theirs.text
    assert bootstrap.status_code == 201, bootstrap.text
    assert "Idempotency-Replayed" not in theirs.headers
    assert len({mine.json()["id"], theirs.json()["id"], bootstrap.json()["id"]}) == 3


def test_human_without_people_scope_is_refused(harness: Harness) -> None:
    headers, admin = harness.federate(scopes=["iam:channel-links"])

    created = harness.create(headers)
    listed = harness.client.get(f"/api/v1/tenants/{harness.tenant_id}/principals", headers=headers)

    assert created.status_code == 403
    assert created.json()["detail"] == "scope_not_granted"
    assert listed.status_code == 403
    denied = harness.audit("people.authenticate")
    assert denied[0][:2] == (admin["principalId"], "denied")
    assert harness.audit("principals.create") == []


def test_agent_token_with_people_scope_is_refused(harness: Harness) -> None:
    agent_id = harness.bootstrap_principal("agent")
    headers = harness.forged(
        principal_id=agent_id, principal_type="agent", credential_id=str(uuid.uuid4())
    )

    created = harness.create(headers)

    assert created.status_code == 403
    assert created.json()["detail"] == "human_required"
    assert harness.audit("people.authenticate") == [(agent_id, "denied", "principal_type:agent")]


def test_service_account_never_gets_people_scope(harness: Harness) -> None:
    account = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/service-accounts",
        headers=BOOTSTRAP,
        json={"displayName": "sa", "audiences": ["iam"], "scopeCeiling": ["iam:people"]},
    ).json()

    response = harness.client.post(
        "/api/v1/tokens/exchange",
        json={
            "clientId": account["clientId"],
            "clientSecret": account["clientSecret"],
            "audience": "iam",
            "scopes": ["iam:people"],
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "scope_not_allowed"


def test_human_pat_never_carries_people_scope(harness: Harness) -> None:
    human_id = harness.bootstrap_principal("human")
    pat = harness.issue_pat(human_id)

    explicit = harness.client.post(
        "/api/v1/platform-access-tokens:exchange",
        json={"token": pat["token"], "audience": "iam", "scopes": ["iam:people"]},
    )
    implicit = harness.client.post(
        "/api/v1/platform-access-tokens:exchange",
        json={"token": pat["token"], "audience": "iam", "scopes": []},
    )
    assert explicit.status_code == 403
    assert implicit.status_code == 200, implicit.text
    assert "iam:people" not in implicit.json()["scope"]

    # Даже подписанный IAM token человека проходит только от federation-входа.
    headers = harness.forged(
        principal_id=human_id,
        principal_type="human",
        credential_id=pat["credential"]["id"],
    )
    refused = harness.create(headers)
    assert refused.status_code == 403
    assert refused.json()["detail"] == "federation_required"


def test_people_scope_manages_only_humans(harness: Harness) -> None:
    headers, admin = harness.federate()
    agent_id = harness.bootstrap_principal("agent")

    created = harness.create(headers, kind="agent")
    linked = harness.link(headers, agent_id)
    disabled = harness.disable(headers, agent_id)

    assert created.status_code == 422
    assert created.json()["detail"] == "human_principal_required"
    assert linked.status_code == 422
    assert disabled.status_code == 422
    assert harness.audit("principals.disable") == [(admin["principalId"], "denied", "kind:agent")]
    agent = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{agent_id}", headers=BOOTSTRAP
    ).json()
    assert agent["status"] == "active"


def test_link_is_onboarding_only(harness: Harness) -> None:
    """Захват аккаунта: своя пара (issuer, subject) к чужому человеку."""

    headers, admin = harness.federate()
    _, colleague = harness.federate(subject="colleague", scopes=[], admin=False)
    newcomer = harness.create(headers).json()["id"]

    to_self = harness.link(headers, admin["principalId"], subject="mine-too")
    with_identity = harness.link(headers, colleague["principalId"], subject="attacker")
    unknown_issuer = harness.link(
        headers, newcomer, subject="attacker", issuer="https://other-idp.example"
    )
    missing = harness.link(headers, str(uuid.uuid4()))

    assert to_self.status_code == 403
    assert to_self.json()["detail"] == "self_link_forbidden"
    assert with_identity.status_code == 409
    assert with_identity.json()["detail"] == "principal_has_identity"
    assert unknown_issuer.status_code == 422
    assert unknown_issuer.json()["detail"] == "identity_provider_unknown"
    assert missing.status_code == 404
    assert missing.json()["detail"] == "principal_not_found"
    denials = harness.denials("external_identities.link")
    assert [row[0] for row in denials] == [admin["principalId"]] * 4
    assert {row[1] for row in denials} == {"principal"}
    assert [row[2].split(" ")[0].split(":")[0] for row in denials] == [
        "self_link_forbidden",
        "identity",
        "issuer",
        "principal_not_found",
    ]
    # Ни одной новой identity: коллега входит по-прежнему только своей.
    rows = harness.client.get("/api/v1/events", headers=BOOTSTRAP).json()["items"]
    linked = [row for row in rows if row["type"] == "external_identity.linked"]
    assert len(linked) == 2

    # Bootstrap остаётся путём для всего прочего.
    rescue = harness.link(BOOTSTRAP, colleague["principalId"], subject="second-login")
    assert rescue.status_code == 201, rescue.text


def test_link_refuses_target_with_disabled_identity(harness: Harness) -> None:
    """Отключённая identity — тоже способ входа: её владелец не новичок."""

    headers, admin = harness.federate()
    person = harness.bootstrap_principal("human")
    assert harness.link(BOOTSTRAP, person, subject="old-login").status_code == 201
    harness.execute(
        "UPDATE external_identities SET status = 'disabled' WHERE principal_id = ?",
        person.replace("-", ""),
    )

    response = harness.link(headers, person, subject="attacker")

    assert response.status_code == 409
    assert response.json()["detail"] == "principal_has_identity"
    [denied] = harness.denials("external_identities.link")
    assert denied[0] == admin["principalId"]
    assert denied[2].startswith("identity:")


def test_link_refuses_target_with_active_pat(harness: Harness) -> None:
    """Человек, входящий только по PAT, identity не имеет, но уже не новичок."""

    headers, admin = harness.federate()
    person = harness.bootstrap_principal("human")
    pat = harness.issue_pat(person)

    response = harness.link(headers, person, subject="attacker")

    assert response.status_code == 409
    assert response.json()["detail"] == "principal_has_credential"
    assert harness.denials("external_identities.link") == [
        (admin["principalId"], "principal", f"pat:{pat['credential']['id']}")
    ]

    # Отозванный PAT способом входа не считается: онбординг открыт.
    revoked = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/platform-access-tokens/"
        f"{pat['credential']['id']}:revoke",
        headers=BOOTSTRAP,
    )
    assert revoked.status_code == 204, revoked.text
    onboarded = harness.link(headers, person, subject="newcomer")
    assert onboarded.status_code == 201, onboarded.text


def test_link_allows_target_with_expired_pat(harness: Harness) -> None:
    """Истёкший, но не отозванный PAT способом входа не считается."""

    headers, _ = harness.federate()
    person = harness.bootstrap_principal("human")
    pat = harness.issue_pat(person)
    # SQLite хранит время без зоны: проверка приводит его к UTC.
    harness.execute(
        "UPDATE platform_access_tokens SET expires_at = '2000-01-01 00:00:00.000000' WHERE id = ?",
        pat["credential"]["id"].replace("-", ""),
    )

    response = harness.link(headers, person, subject="newcomer")

    assert response.status_code == 201, response.text
    assert harness.denials("external_identities.link") == []


def test_link_refuses_people_admin_without_identity(harness: Harness) -> None:
    """Identity к администратору дала бы вызывающему второй admin-вход."""

    headers, admin = harness.federate()
    person = harness.bootstrap_principal("human")
    added = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/groups/{harness.admin_group_id}/members",
        headers=BOOTSTRAP,
        json={"principalId": person},
    )
    assert added.status_code == 201, added.text

    response = harness.link(headers, person, subject="attacker")

    assert response.status_code == 403
    assert response.json()["detail"] == "people_admin_protected"
    assert harness.denials("external_identities.link") == [
        (admin["principalId"], "principal", "group:people-admins")
    ]


def test_federation_never_creates_the_people_admin_group(harness: Harness) -> None:
    """Группу администраторов заводит только bootstrap, иначе её раздаёт IdP."""

    harness.tenant_id = harness.tenant("tenant-c", admin_group=False)

    refused = harness.exchange(subject="admin", scopes=["iam:people"], admin=True)

    assert refused.status_code == 403
    assert refused.json()["detail"] == "scope_not_allowed"
    with sqlite3.connect(harness.database_path) as connection:
        [(count,)] = connection.execute(
            "SELECT count(*) FROM groups WHERE key = 'people-admins' AND tenant_id = ?",
            (harness.tenant_id.replace("-", ""),),
        )
    assert count == 0

    # Группа с этим ключом не от bootstrap (заведённая до запрета) прав не даёт.
    harness.execute(
        "INSERT INTO groups (id, tenant_id, key, name, source, status, created_at) "
        "VALUES (?, ?, 'people-admins', 'people-admins', 'federated', 'active', "
        "CURRENT_TIMESTAMP)",
        uuid.uuid4().hex,
        harness.tenant_id.replace("-", ""),
    )
    still_refused = harness.exchange(subject="admin", scopes=["iam:people"], admin=True)
    assert still_refused.status_code == 403
    assert still_refused.json()["detail"] == "scope_not_allowed"


def test_disable_refuses_self_and_other_admins(harness: Harness) -> None:
    headers, admin = harness.federate()
    _, other_admin = harness.federate(subject="other-admin")

    self_disable = harness.disable(headers, admin["principalId"])
    admin_disable = harness.disable(headers, other_admin["principalId"])
    missing = harness.disable(headers, str(uuid.uuid4()))

    assert self_disable.status_code == 409
    assert self_disable.json()["detail"] == "self_disable_forbidden"
    assert admin_disable.status_code == 403
    assert admin_disable.json()["detail"] == "people_admin_protected"
    assert missing.status_code == 404
    assert [(row[0], row[1], row[2]) for row in harness.denials("principals.disable")] == [
        (admin["principalId"], "principal", "self_disable_forbidden"),
        (admin["principalId"], "principal", "people_admin_protected"),
        (admin["principalId"], "principal", "principal_not_found"),
    ]
    # Bootstrap администратора людей отключает.
    rescue = harness.disable(BOOTSTRAP, other_admin["principalId"])
    assert rescue.status_code == 200, rescue.text


def test_disable_human_closes_login_and_is_audited(harness: Harness) -> None:
    headers, admin = harness.federate()
    _, other = harness.federate(subject="colleague", scopes=["iam:channel-links"], admin=False)

    disabled = harness.disable(headers, other["principalId"])

    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["status"] == "disabled"
    [audit] = harness.audit("principals.disable")
    assert audit[:2] == (admin["principalId"], "allowed")
    # Federation-вход отключённого человека закрыт.
    relogin = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/federation:exchange",
        json={
            "identityProvider": "keycloak",
            "token": harness.idp.token(subject="colleague"),
            "audience": "iam",
            "scopes": [],
        },
    )
    assert relogin.status_code == 403


def test_disabled_identity_closes_the_path_before_token_expiry(harness: Harness) -> None:
    headers, admin = harness.federate()
    harness.execute(
        "UPDATE external_identities SET status = 'disabled' WHERE principal_id = ?",
        admin["principalId"].replace("-", ""),
    )

    response = harness.create(headers)

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_token"
    # Подпись проверена — отказ относится к человеку и пишется в audit.
    assert harness.denials("people.authenticate") == [
        (admin["principalId"], "principal", "closed:identity")
    ]


def test_foreign_tenant_and_invalid_bearer_are_refused(harness: Harness) -> None:
    headers, _ = harness.federate()
    other_tenant = harness.tenant("tenant-b")

    foreign = harness.client.get(f"/api/v1/tenants/{other_tenant}/principals", headers=headers)
    garbage = harness.create({"Authorization": "Bearer not-a-token"})
    nothing = harness.create({})
    # Неверный bootstrap не уступает место Bearer.
    wrong_bootstrap = harness.create({**headers, "X-IAM-Bootstrap-Token": "wrong"})

    assert foreign.status_code == 403
    assert foreign.json()["detail"] == "tenant_mismatch"
    assert garbage.status_code == 401
    assert nothing.status_code == 401
    assert nothing.json()["detail"] == "unauthorized"
    assert wrong_bootstrap.status_code == 401


def test_bootstrap_path_keeps_working_and_is_audited_as_bootstrap(harness: Harness) -> None:
    agent_id = harness.bootstrap_principal("agent")
    service = harness.bootstrap_principal("workload")

    listed = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals",
        headers=BOOTSTRAP,
        params={"limit": 1},
    )
    assert listed.status_code == 200, listed.text
    page = listed.json()
    assert len(page["items"]) == 1
    rest = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals",
        headers=BOOTSTRAP,
        params={"after": page["next_after"]},
    ).json()
    assert {page["items"][0]["id"], *(item["id"] for item in rest["items"])} == {
        agent_id,
        service,
    }
    assert rest["next_after"] is None

    disabled = harness.disable(BOOTSTRAP, agent_id)
    assert disabled.status_code == 200, disabled.text
    assert [row[0] for row in harness.audit("principals.create")] == ["bootstrap", "bootstrap"]
    assert harness.audit("principals.disable")[0][:2] == ("bootstrap", "allowed")


# --- чтение external identities (TASK-000908) ----------------------------


def find_identity(harness: Harness, headers: dict[str, str], params: dict[str, str]):
    return harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/external-identities",
        headers=headers,
        params=params,
    )


def test_find_external_identity_by_exact_pair(harness: Harness) -> None:
    headers, _ = harness.federate()
    person = harness.bootstrap_principal("human")
    linked = harness.link(BOOTSTRAP, person, subject="second")
    assert linked.status_code == 201, linked.text

    found = find_identity(harness, headers, {"issuer": harness.idp.issuer, "subject": "second"})
    other_subject = find_identity(
        harness, headers, {"issuer": harness.idp.issuer, "subject": "secon"}
    )
    other_issuer = find_identity(
        harness, headers, {"issuer": "https://other.example", "subject": "second"}
    )

    assert found.status_code == 200, found.text
    assert found.json() == {
        "items": [
            {
                "id": linked.json()["id"],
                "principal_id": person,
                "issuer": harness.idp.issuer,
                "subject": "second",
                "status": "active",
            }
        ]
    }
    assert other_subject.status_code == 200
    assert other_subject.json() == {"items": []}
    assert other_issuer.json() == {"items": []}


def test_find_external_identity_requires_both_params(harness: Harness) -> None:
    headers, _ = harness.federate()

    no_subject = find_identity(harness, headers, {"issuer": harness.idp.issuer})
    no_issuer = find_identity(harness, headers, {"subject": "admin"})
    empty = find_identity(harness, headers, {"issuer": harness.idp.issuer, "subject": ""})

    assert no_subject.status_code == 422
    assert no_issuer.status_code == 422
    assert empty.status_code == 422


def test_external_identities_of_principal(harness: Harness) -> None:
    headers, admin = harness.federate()
    person = harness.bootstrap_principal("human")
    first = harness.link(BOOTSTRAP, person, subject="first-login")
    second = harness.link(BOOTSTRAP, person, subject="second-login")
    assert first.status_code == second.status_code == 201
    loner = harness.bootstrap_principal("human")

    listed = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{person}/external-identities",
        headers=headers,
    )
    empty = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{loner}/external-identities",
        headers=headers,
    )
    # Администратор видит и identity другого администратора (и свою): чтение
    # по `iam:people` охватывает всех principals tenant'а (ADR-0002, п. 5).
    own = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{admin['principalId']}"
        "/external-identities",
        headers=headers,
    )
    missing = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{uuid.uuid4()}/external-identities",
        headers=headers,
    )

    assert listed.status_code == 200, listed.text
    assert {item["subject"] for item in listed.json()["items"]} == {"first-login", "second-login"}
    assert {item["principal_id"] for item in listed.json()["items"]} == {person}
    assert empty.json() == {"items": []}
    assert own.status_code == 200, own.text
    assert [item["subject"] for item in own.json()["items"]] == ["admin"]
    assert missing.status_code == 404
    assert missing.json()["detail"] == "principal_not_found"


def test_external_identities_are_scoped_to_tenant(harness: Harness) -> None:
    headers, _ = harness.federate()
    other_tenant = harness.tenant("tenant-b")
    stranger = harness.client.post(
        f"/api/v1/tenants/{other_tenant}/principals",
        headers=BOOTSTRAP,
        json={"kind": "human", "displayName": "Stranger"},
    ).json()["id"]
    linked = harness.client.post(
        f"/api/v1/tenants/{other_tenant}/principals/{stranger}/external-identities",
        headers=BOOTSTRAP,
        json={"issuer": harness.idp.issuer, "subject": "stranger"},
    )
    assert linked.status_code == 201, linked.text

    # Identity Principal чужого tenant'а в своём не видна.
    found = find_identity(harness, headers, {"issuer": harness.idp.issuer, "subject": "stranger"})
    by_principal = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{stranger}/external-identities",
        headers=headers,
    )
    # Token одного tenant'а в путь другого не проходит.
    foreign_path = harness.client.get(
        f"/api/v1/tenants/{other_tenant}/external-identities",
        headers=headers,
        params={"issuer": harness.idp.issuer, "subject": "stranger"},
    )
    foreign_list = harness.client.get(
        f"/api/v1/tenants/{other_tenant}/principals/{stranger}/external-identities",
        headers=headers,
    )

    assert found.status_code == 200
    assert found.json() == {"items": []}
    assert by_principal.status_code == 404
    assert foreign_path.status_code == 403
    assert foreign_path.json()["detail"] == "tenant_mismatch"
    assert foreign_list.status_code == 403
    assert foreign_list.json()["detail"] == "tenant_mismatch"


def test_reading_external_identities_requires_people_scope(harness: Harness) -> None:
    headers, _ = harness.federate(scopes=[])
    person = harness.bootstrap_principal("human")
    assert harness.link(BOOTSTRAP, person, subject="second").status_code == 201

    found = find_identity(harness, headers, {"issuer": harness.idp.issuer, "subject": "second"})
    listed = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{person}/external-identities",
        headers=headers,
    )
    anonymous = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/external-identities",
        params={"issuer": harness.idp.issuer, "subject": "second"},
    )

    assert found.status_code == 403
    assert found.json()["detail"] == "scope_not_granted"
    assert listed.status_code == 403
    assert listed.json()["detail"] == "scope_not_granted"
    assert anonymous.status_code == 401


def test_disabled_principal_identity_is_returned_with_its_status(harness: Harness) -> None:
    headers, _ = harness.federate()
    person = harness.bootstrap_principal("human")
    assert harness.link(BOOTSTRAP, person, subject="leaver").status_code == 201
    assert harness.disable(BOOTSTRAP, person).status_code == 200

    found = find_identity(harness, headers, {"issuer": harness.idp.issuer, "subject": "leaver"})
    listed = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{person}/external-identities",
        headers=headers,
    )

    assert found.status_code == 200, found.text
    [item] = found.json()["items"]
    assert item["principal_id"] == person
    assert listed.json()["items"] == [item]
    # `status` — статус самой identity: отключение Principal её не меняет
    # (вход закрывает статус Principal, его отдаёт GET principal).
    assert item["status"] == "active"
    principal = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{person}", headers=headers
    )
    assert principal.json()["status"] == "disabled"

    harness.execute(
        "UPDATE external_identities SET status = 'disabled' WHERE principal_id = ?",
        person.replace("-", ""),
    )
    found = find_identity(harness, headers, {"issuer": harness.idp.issuer, "subject": "leaver"})
    assert found.json()["items"][0]["status"] == "disabled"


def test_bootstrap_reads_external_identities(harness: Harness) -> None:
    person = harness.bootstrap_principal("human")
    linked = harness.link(BOOTSTRAP, person, subject="boot")
    assert linked.status_code == 201, linked.text

    found = find_identity(harness, BOOTSTRAP, {"issuer": harness.idp.issuer, "subject": "boot"})
    listed = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{person}/external-identities",
        headers=BOOTSTRAP,
    )

    assert found.status_code == 200, found.text
    assert [item["id"] for item in found.json()["items"]] == [linked.json()["id"]]
    assert listed.status_code == 200, listed.text
    assert listed.json() == found.json()


def test_identity_of_principal_with_disabled_membership_is_hidden(harness: Harness) -> None:
    headers, _ = harness.federate()
    person = harness.bootstrap_principal("human")
    assert harness.link(BOOTSTRAP, person, subject="gone").status_code == 201
    harness.execute(
        "UPDATE tenant_memberships SET status = 'disabled' WHERE principal_id = ?",
        person.replace("-", ""),
    )

    found = find_identity(harness, headers, {"issuer": harness.idp.issuer, "subject": "gone"})
    listed = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{person}/external-identities",
        headers=headers,
    )

    assert found.status_code == 200
    assert found.json() == {"items": []}
    assert listed.status_code == 404
    assert listed.json()["detail"] == "principal_not_found"


def test_principal_in_two_tenants_is_visible_in_both(harness: Harness) -> None:
    headers, _ = harness.federate()
    person = harness.bootstrap_principal("human")
    linked = harness.link(BOOTSTRAP, person, subject="shared")
    assert linked.status_code == 201, linked.text
    other_tenant = harness.tenant("tenant-b")
    harness.execute(
        "INSERT INTO tenant_memberships (tenant_id, principal_id, status, created_at) "
        "VALUES (?, ?, 'active', '2026-09-29 00:00:00.000000')",
        other_tenant.replace("-", ""),
        person.replace("-", ""),
    )
    pair = {"issuer": harness.idp.issuer, "subject": "shared"}

    own = find_identity(harness, headers, pair)
    other = harness.client.get(
        f"/api/v1/tenants/{other_tenant}/external-identities", headers=BOOTSTRAP, params=pair
    )
    other_list = harness.client.get(
        f"/api/v1/tenants/{other_tenant}/principals/{person}/external-identities",
        headers=BOOTSTRAP,
    )

    expected = [linked.json()["id"]]
    assert [item["id"] for item in own.json()["items"]] == expected
    assert other.status_code == 200, other.text
    assert [item["id"] for item in other.json()["items"]] == expected
    assert [item["id"] for item in other_list.json()["items"]] == expected


# --- :enable (ADR-0002, п. 12; TASK-000907) -------------------------------


def exchange_pat(harness: Harness, token: str):
    return harness.client.post(
        "/api/v1/platform-access-tokens:exchange",
        json={"token": token, "audience": "iam", "scopes": []},
    )


def test_enable_restores_idp_login_but_not_revoked_credentials(harness: Harness) -> None:
    headers, admin = harness.federate()
    _, colleague = harness.federate(subject="colleague", scopes=[], admin=False)
    person = colleague["principalId"]
    pat = harness.issue_pat(person)
    assert exchange_pat(harness, pat["token"]).status_code == 200

    disabled = harness.disable(headers, person)
    assert disabled.json()["revokedCredentials"] == 1
    closed = harness.exchange(subject="colleague", scopes=[], admin=False)
    assert closed.status_code == 403

    enabled = harness.enable(headers, person, key="enable-colleague")

    assert enabled.status_code == 200, enabled.text
    body = enabled.json()
    assert body["principalId"] == person
    assert body["status"] == "active"
    assert body["previousStatus"] == "disabled"
    assert "Idempotency-Replayed" not in enabled.headers
    # Приёмка: отключённый человек после `:enable` входит через IdP.
    relogin = harness.exchange(subject="colleague", scopes=[], admin=False)
    assert relogin.status_code == 200, relogin.text
    assert relogin.json()["principalId"] == person
    # Отозванный при отключении PAT остаётся отозванным.
    revoked = exchange_pat(harness, pat["token"])
    assert revoked.status_code == 401
    assert revoked.json()["detail"] == "invalid_token"
    listed = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/platform-access-tokens",
        headers=BOOTSTRAP,
        params={"principalId": person, "includeRevoked": "true"},
    )
    [credential] = listed.json()
    assert credential["revokedAt"] is not None
    # External identity осталась привязанной.
    identities = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{person}/external-identities",
        headers=headers,
    )
    [identity] = identities.json()["items"]
    assert (identity["subject"], identity["status"]) == ("colleague", "active")
    # Audit называет вызывающего, outbox сообщает о включении.
    [audit] = harness.audit("principals.enable")
    assert audit[:2] == (admin["principalId"], "allowed")
    assert audit[2].startswith("previous:disabled scope:iam:people identity:")
    with sqlite3.connect(harness.database_path) as connection:
        events = [
            row[0]
            for row in connection.execute(
                "SELECT type FROM outbox_events WHERE aggregate_id = ? ORDER BY rowid",
                (person.replace("-", ""),),
            )
        ]
    assert events[-2:] == ["principal.disabled", "principal.enabled"]


def test_enable_is_idempotent_by_key(harness: Harness) -> None:
    headers, _ = harness.federate()
    person = harness.bootstrap_principal("human")
    other = harness.bootstrap_principal("human")
    assert harness.disable(BOOTSTRAP, person).status_code == 200

    missing_key = harness.enable(headers, person)
    first = harness.enable(headers, person, key="k-1")
    repeat = harness.enable(headers, person, key="k-1")

    assert missing_key.status_code == 400
    assert missing_key.json()["detail"] == "idempotency_key_required"
    assert first.status_code == 200, first.text
    assert repeat.status_code == 200, repeat.text
    assert repeat.headers["Idempotency-Replayed"] == "true"
    assert repeat.json() == first.json()
    assert len(harness.audit("principals.enable")) == 1

    # Повтор после нового отключения не включает Principal заново.
    assert harness.disable(BOOTSTRAP, person).status_code == 200
    late = harness.enable(headers, person, key="k-1")
    assert late.status_code == 200
    assert late.headers["Idempotency-Replayed"] == "true"
    assert late.json()["status"] == "disabled"
    status = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{person}", headers=BOOTSTRAP
    )
    assert status.json()["status"] == "disabled"

    # Тот же ключ для другого Principal — конфликт с записью в audit.
    reused = harness.enable(headers, other, key="k-1")
    assert reused.status_code == 409
    assert reused.json()["detail"] == "idempotency_key_reused"
    assert harness.denials("principals.enable")[-1][2] == "idempotency_key_reused"

    # Включение активного — no-op, без события.
    noop = harness.enable(headers, other, key="k-2")
    assert noop.status_code == 200, noop.text
    assert noop.json()["previousStatus"] == "active"
    with sqlite3.connect(harness.database_path) as connection:
        [(count,)] = connection.execute(
            "SELECT count(*) FROM outbox_events WHERE type = 'principal.enabled' "
            "AND aggregate_id = ?",
            (other.replace("-", ""),),
        )
    assert count == 0


def test_enable_protections(harness: Harness) -> None:
    headers, admin = harness.federate()
    _, other_admin = harness.federate(subject="other-admin")
    fleet = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/groups",
        headers=BOOTSTRAP,
        json={"key": "fleet-admins", "name": "Fleet admins"},
    )
    assert fleet.status_code == 201, fleet.text
    fleet_admin = harness.bootstrap_principal("human")
    added = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/groups/{fleet.json()['id']}/members",
        headers=BOOTSTRAP,
        json={"principalId": fleet_admin},
    )
    assert added.status_code == 201, added.text
    agent = harness.bootstrap_principal("agent")
    for target in (other_admin["principalId"], fleet_admin, agent):
        assert harness.disable(BOOTSTRAP, target).status_code == 200

    self_enable = harness.enable(headers, admin["principalId"], key="self")
    foreign_group = harness.enable(headers, fleet_admin, key="fleet")
    not_human = harness.enable(headers, agent, key="agent")
    missing = harness.enable(headers, str(uuid.uuid4()), key="missing")
    # Администратора людей включает член той же группы.
    same_group = harness.enable(headers, other_admin["principalId"], key="admin")

    assert self_enable.status_code == 409
    assert self_enable.json()["detail"] == "self_enable_forbidden"
    assert foreign_group.status_code == 403
    assert foreign_group.json()["detail"] == "people_admin_protected"
    assert not_human.status_code == 422
    assert not_human.json()["detail"] == "human_principal_required"
    assert missing.status_code == 404
    assert same_group.status_code == 200, same_group.text
    assert harness.denials("principals.enable") == [
        (admin["principalId"], "principal", "self_enable_forbidden"),
        (admin["principalId"], "principal", "group:fleet-admins"),
        (admin["principalId"], "principal", "kind:agent"),
        (admin["principalId"], "principal", "principal_not_found"),
    ]
    # Bootstrap включает любого.
    rescue = harness.enable(BOOTSTRAP, fleet_admin)
    assert rescue.status_code == 200, rescue.text
    assert harness.enable(BOOTSTRAP, agent).status_code == 200


def test_enable_refuses_paused_and_provisioned(harness: Harness) -> None:
    paused = harness.bootstrap_principal("human")
    provisioned = harness.bootstrap_principal("human")
    harness.execute("UPDATE principals SET status = 'paused' WHERE id = ?", paused.replace("-", ""))
    assert harness.disable(BOOTSTRAP, provisioned).status_code == 200
    # Человека отключил источник провижининга (SCIM `active: false`).
    harness.execute(
        "INSERT INTO scim_users (id, tenant_id, provisioning_source_id, external_id, "
        "user_name, display_name, principal_id, active, version, created_at, updated_at) "
        "VALUES (?, ?, ?, 'ext-1', 'leaver', 'Leaver', ?, 0, 1, CURRENT_TIMESTAMP, "
        "CURRENT_TIMESTAMP)",
        uuid.uuid4().hex,
        harness.tenant_id.replace("-", ""),
        uuid.uuid4().hex,
        provisioned.replace("-", ""),
    )

    paused_enable = harness.enable(BOOTSTRAP, paused)
    provisioned_enable = harness.enable(BOOTSTRAP, provisioned)

    assert paused_enable.status_code == 409
    assert paused_enable.json()["detail"] == "principal_paused"
    assert provisioned_enable.status_code == 409
    assert provisioned_enable.json()["detail"] == "principal_provisioned"


def test_enable_does_not_revive_sessions_issued_before(harness: Harness) -> None:
    headers, _ = harness.federate()
    old_headers, other_admin = harness.federate(subject="other-admin")
    target = other_admin["principalId"]
    assert harness.disable(BOOTSTRAP, target).status_code == 200
    assert harness.enable(headers, target, key="revive").status_code == 200
    # Token и включение в тесте укладываются в одну секунду; сдвигаем момент
    # включения так, как он лёг бы в жизни — позже выпуска token.
    harness.execute(
        "UPDATE principal_enablements SET enabled_at = datetime(enabled_at, '+2 seconds') "
        "WHERE principal_id = ?",
        target.replace("-", ""),
    )

    stale = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals", headers=old_headers
    )

    assert stale.status_code == 401
    assert stale.json()["detail"] == "invalid_token"
    assert harness.denials("people.authenticate")[-1] == (target, "principal", "closed:session")


def test_scim_reactivation_does_not_revive_sessions_issued_before(harness: Harness) -> None:
    """SCIM `active: true` — такое же включение, как `:enable` (TASK-000972).

    Без записи включения token, выпущенный до отключения в кадровой системе,
    после реактивации снова проходил бы путь `iam:people`.
    """

    old_headers, other_admin = harness.federate(subject="other-admin")
    target = other_admin["principalId"]
    tenant = harness.tenant_id
    audience = harness.client.post(
        f"/api/v1/tenants/{tenant}/audiences",
        headers=BOOTSTRAP,
        json={"key": "iam-scim", "allowedScopes": ["scim:write"]},
    )
    assert audience.status_code == 201, audience.text
    account = harness.client.post(
        f"/api/v1/tenants/{tenant}/service-accounts",
        headers=BOOTSTRAP,
        json={"displayName": "hr", "audiences": ["iam-scim"], "scopeCeiling": ["scim:write"]},
    ).json()
    scim_token = harness.client.post(
        "/api/v1/tokens/exchange",
        json={
            "clientId": account["clientId"],
            "clientSecret": account["clientSecret"],
            "audience": "iam-scim",
            "scopes": ["scim:write"],
        },
    ).json()["accessToken"]
    source = harness.client.post(
        f"/api/v1/tenants/{tenant}/provisioning-sources",
        headers=BOOTSTRAP,
        json={
            "key": "hr-scim",
            "kind": "scim",
            "identityProvider": "keycloak",
            "servicePrincipalId": account["principalId"],
        },
    )
    assert source.status_code == 201, source.text
    # Кадровая система ведёт уже вошедшего человека.
    scim_user = uuid.uuid4()
    harness.execute(
        "INSERT INTO scim_users (id, tenant_id, provisioning_source_id, external_id, "
        "user_name, display_name, principal_id, active, version, created_at, updated_at) "
        "VALUES (?, ?, ?, 'hr-1', 'other-admin', 'Other admin', ?, 1, 1, CURRENT_TIMESTAMP, "
        "CURRENT_TIMESTAMP)",
        scim_user.hex,
        tenant.replace("-", ""),
        source.json()["id"].replace("-", ""),
        target.replace("-", ""),
    )

    def set_active(value: bool):
        return harness.client.patch(
            f"/scim/v2/Users/{scim_user}",
            headers={"Authorization": f"Bearer {scim_token}"},
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "path": "active", "value": value}],
            },
        )

    assert set_active(False).status_code == 200
    reactivated = set_active(True)
    assert reactivated.status_code == 200, reactivated.text
    # Повтор `active: true` — не переход: второй записи и события нет.
    assert set_active(True).status_code == 200
    # Token и реактивация укладываются в одну секунду; сдвигаем момент
    # включения так, как он лёг бы в жизни — позже выпуска token.
    harness.execute(
        "UPDATE principal_enablements SET enabled_at = datetime(enabled_at, '+2 seconds') "
        "WHERE principal_id = ?",
        target.replace("-", ""),
    )

    stale = harness.client.get(f"/api/v1/tenants/{tenant}/principals", headers=old_headers)

    assert stale.status_code == 401
    assert stale.json()["detail"] == "invalid_token"
    assert harness.denials("people.authenticate")[-1] == (target, "principal", "closed:session")
    with sqlite3.connect(harness.database_path) as connection:
        records = list(
            connection.execute(
                "SELECT previous_status, idempotency_key FROM principal_enablements "
                "WHERE principal_id = ?",
                (target.replace("-", ""),),
            )
        )
        events = list(
            connection.execute(
                "SELECT payload FROM outbox_events WHERE type = 'principal.enabled' "
                "AND aggregate_id = ?",
                (target.replace("-", ""),),
            )
        )
    assert records == [("disabled", None)]
    [(payload,)] = events
    assert "sessionsNotBefore" in payload
    # Новый вход через IdP после реактивации работает.
    assert harness.exchange(subject="other-admin", scopes=[], admin=True).status_code == 200


def test_parallel_enable_emits_one_event(harness: Harness, monkeypatch) -> None:
    """Два bootstrap `:enable` без ключа: переход и событие — только у одного.

    Гонка воспроизводится детерминированно: пока запрос проходит проверки,
    «параллельный» включает Principal и фиксируется. Условный UPDATE
    проигравшего не находит строки в `disabled` и отвечает no-op.
    """

    from iam_service.pat import routes

    person = harness.bootstrap_principal("human")
    assert harness.disable(BOOTSTRAP, person).status_code == 200
    original = routes.require_human_target

    async def concurrent_winner(*args, **kwargs):
        await original(*args, **kwargs)
        harness.execute(
            "UPDATE principals SET status = 'active' WHERE id = ?", person.replace("-", "")
        )

    monkeypatch.setattr(routes, "require_human_target", concurrent_winner)
    loser = harness.enable(BOOTSTRAP, person)
    monkeypatch.undo()

    assert loser.status_code == 200, loser.text
    assert loser.json()["previousStatus"] == "active"
    assert loser.json()["status"] == "active"
    with sqlite3.connect(harness.database_path) as connection:
        [(events,)] = connection.execute(
            "SELECT count(*) FROM outbox_events WHERE type = 'principal.enabled' "
            "AND aggregate_id = ?",
            (person.replace("-", ""),),
        )
        [(records,)] = connection.execute(
            "SELECT count(*) FROM principal_enablements WHERE principal_id = ?",
            (person.replace("-", ""),),
        )
    # Проигравший не пишет ни события, ни момента включения.
    assert (events, records) == (0, 0)
    assert harness.audit("principals.enable")[-1][2] == "previous:active"
    # Последовательные включения по-прежнему дают ровно одно событие.
    assert harness.disable(BOOTSTRAP, person).status_code == 200
    first = harness.enable(BOOTSTRAP, person)
    second = harness.enable(BOOTSTRAP, person)
    assert first.json()["previousStatus"] == "disabled"
    assert second.json()["previousStatus"] == "active"
    with sqlite3.connect(harness.database_path) as connection:
        [(events,)] = connection.execute(
            "SELECT count(*) FROM outbox_events WHERE type = 'principal.enabled' "
            "AND aggregate_id = ?",
            (person.replace("-", ""),),
        )
    assert events == 1


def test_enable_lists_source_statuses_explicitly(harness: Harness, monkeypatch) -> None:
    """Статус вне явного списка — отказ, а не молчаливое включение."""

    from iam_service.pat import routes

    person = harness.bootstrap_principal("human")
    assert harness.disable(BOOTSTRAP, person).status_code == 200
    assert "disabled" in routes.ENABLE_SOURCE_STATUSES
    # Будто `disabled` не входит в список: такой статус `:enable` не трогает.
    monkeypatch.setattr(routes, "ENABLE_SOURCE_STATUSES", frozenset())

    refused = harness.enable(BOOTSTRAP, person)

    assert refused.status_code == 409
    assert refused.json()["detail"] == "principal_status_not_enableable"
    assert harness.denials("principals.enable")[-1][2] == "status:disabled"
    status = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{person}", headers=BOOTSTRAP
    )
    assert status.json()["status"] == "disabled"


def test_enable_route_is_in_openapi(harness: Harness) -> None:
    schema = harness.client.get("/openapi.json").json()
    operation = schema["paths"]["/api/v1/tenants/{tenant_id}/principals/{principal_id}:enable"]
    assert set(operation["post"]["responses"]) >= {"200", "400", "403", "404", "409", "422"}
    [enabled] = [name for name in schema["components"]["schemas"] if name == "PrincipalEnabled"]
    assert set(schema["components"]["schemas"][enabled]["properties"]) == {
        "principalId",
        "status",
        "previousStatus",
        "enabledAt",
    }
