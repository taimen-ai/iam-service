"""Привилегированные scope (`fleet:admin` и др.) — только члену группы и по явному запросу.

Приёмка (ADR-0003): федеративный человек вне группы `fleet-admins` на запрос
`fleet:admin` получает `403 scope_not_allowed`, при пустом запросе
`fleet:admin` не выдаётся никому; член группы получает scope по явному запросу.
Negative matrix по образцу `iam:people`: группу не заводит federation, группа
не от bootstrap прав не даёт, выход из группы закрывает следующий выпуск, PAT
привилегированный scope не переносит, identity к члену группы по `iam:people`
не привязать.
"""

from __future__ import annotations

import sqlite3
import uuid
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
# Upstream-группы IdP, которые провайдер проецирует в группы привилегированных scope.
FLEET_UPSTREAM = "platform-fleet-admins"
PEOPLE_UPSTREAM = "platform-people-admins"
AUDIENCE_SCOPES = {
    "iam": ["iam:agents", "iam:people"],
    "fleet": ["fleet:admin", "fleet:read"],
}


def signing_key_pem() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


class Harness:
    def __init__(self, client: TestClient, database_path, idp: FakeIdentityProvider) -> None:
        self.client = client
        self.database_path = database_path
        self.idp = idp
        self.tenant_id = ""
        self.groups: dict[str, str] = {}

    def tenant(self, slug: str = "tenant-a", *, groups: tuple[str, ...] = ("fleet-admins",)):
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
                "groupMappings": {
                    FLEET_UPSTREAM: "fleet-admins",
                    PEOPLE_UPSTREAM: "people-admins",
                },
            },
        )
        assert provider.status_code == 201, provider.text
        self.tenant_id = tenant_id
        for key in groups:
            group = self.client.post(
                f"/api/v1/tenants/{tenant_id}/groups",
                headers=BOOTSTRAP,
                json={"key": key, "name": key},
            )
            assert group.status_code == 201, group.text
            self.groups[key] = group.json()["id"]
        return tenant_id

    def exchange(
        self,
        *,
        subject: str,
        scopes: list[str],
        groups: list[str] = (),
        audience: str = "fleet",
    ):
        return self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/federation:exchange",
            json={
                "identityProvider": "keycloak",
                "token": self.idp.token(
                    subject=subject, claims={"acr": "1", "groups": list(groups)}
                ),
                "audience": audience,
                "scopes": scopes,
            },
        )

    def add_member(self, group_key: str, principal_id: str) -> None:
        added = self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/groups/{self.groups[group_key]}/members",
            headers=BOOTSTRAP,
            json={"principalId": principal_id},
        )
        assert added.status_code == 201, added.text

    def audit(self, action: str) -> list[tuple[str, str, str]]:
        with sqlite3.connect(self.database_path) as connection:
            return list(
                connection.execute(
                    "SELECT actor_ref, outcome, reason FROM audit_events WHERE action = ? "
                    "ORDER BY rowid",
                    (action,),
                )
            )

    def execute(self, sql: str, *params: Any) -> None:
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(sql, params)


def claims(response) -> dict[str, Any]:
    return jwt.decode(response.json()["accessToken"], options={"verify_signature": False})


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
        harness = Harness(client, database_path, idp)
        harness.tenant()
        yield harness


def test_fleet_admin_only_for_group_members_and_only_on_request(harness: Harness) -> None:
    outsider = harness.exchange(subject="outsider", scopes=["fleet:admin"])
    mixed = harness.exchange(subject="outsider", scopes=["fleet:admin", "fleet:read"])
    outsider_implicit = harness.exchange(subject="outsider", scopes=[])
    member_implicit = harness.exchange(subject="member", scopes=[], groups=[FLEET_UPSTREAM])
    member_explicit = harness.exchange(
        subject="member", scopes=["fleet:admin"], groups=[FLEET_UPSTREAM]
    )

    assert outsider.status_code == 403
    assert outsider.json()["detail"] == "scope_not_allowed"
    assert mixed.status_code == 403
    assert mixed.json()["detail"] == "scope_not_allowed"
    assert outsider_implicit.status_code == 200, outsider_implicit.text
    assert outsider_implicit.json()["scope"] == ["fleet:read"]
    # Потолок token вне группы привилегированного scope не содержит.
    assert claims(outsider_implicit)["scope_ceiling"] == ["fleet:read"]
    # Пустой запрос не выдаёт `fleet:admin` даже члену группы.
    assert member_implicit.status_code == 200, member_implicit.text
    assert member_implicit.json()["scope"] == ["fleet:read"]
    assert claims(member_implicit)["scope_ceiling"] == ["fleet:admin", "fleet:read"]
    assert member_explicit.status_code == 200, member_explicit.text
    assert member_explicit.json()["scope"] == ["fleet:admin"]
    assert claims(member_explicit)["scope"] == ["fleet:admin"]

    audit = harness.audit("federation.exchange")
    denied = [row for row in audit if row[1] == "denied"]
    assert [row[0] for row in denied] == [outsider_implicit.json()["principalId"]] * 2
    assert all("scope_not_allowed group:fleet-admins" in row[2] for row in denied)
    # Выдача привилегированного scope видна в журнале вместе с группой.
    granted = [row for row in audit if "privileged:" in row[2]]
    assert len(granted) == 1
    assert granted[0][0] == member_explicit.json()["principalId"]
    assert "privileged:fleet:admin@group:fleet-admins" in granted[0][2]


def test_local_membership_grants_fleet_admin(harness: Harness) -> None:
    """Членство любого источника: bootstrap может добавить человека сам."""

    first = harness.exchange(subject="operator", scopes=["fleet:read"])
    assert first.status_code == 200, first.text
    harness.add_member("fleet-admins", first.json()["principalId"])

    granted = harness.exchange(subject="operator", scopes=["fleet:admin"])

    assert granted.status_code == 200, granted.text
    assert granted.json()["scope"] == ["fleet:admin"]


def test_leaving_group_closes_the_next_issue(harness: Harness) -> None:
    """Для чужого audience членство фиксируется в момент выдачи (ADR-0003)."""

    member = harness.exchange(subject="member", scopes=["fleet:admin"], groups=[FLEET_UPSTREAM])
    assert member.status_code == 200, member.text

    # IdP больше не присылает группу: проекция снимает federated-членство.
    left = harness.exchange(subject="member", scopes=["fleet:admin"])

    assert left.status_code == 403
    assert left.json()["detail"] == "scope_not_allowed"


def test_disabled_group_grants_nothing(harness: Harness) -> None:
    harness.execute(
        "UPDATE groups SET status = 'disabled' WHERE key = 'fleet-admins' AND tenant_id = ?",
        harness.tenant_id.replace("-", ""),
    )

    refused = harness.exchange(subject="member", scopes=["fleet:admin"], groups=[FLEET_UPSTREAM])

    assert refused.status_code == 403
    assert refused.json()["detail"] == "scope_not_allowed"


def test_federation_never_creates_the_fleet_admin_group(harness: Harness) -> None:
    """Группу заводит только bootstrap, иначе `fleet:admin` раздаёт IdP."""

    harness.tenant("tenant-b", groups=())

    refused = harness.exchange(subject="member", scopes=["fleet:admin"], groups=[FLEET_UPSTREAM])

    assert refused.status_code == 403
    assert refused.json()["detail"] == "scope_not_allowed"
    with sqlite3.connect(harness.database_path) as connection:
        [(count,)] = connection.execute(
            "SELECT count(*) FROM groups WHERE key = 'fleet-admins' AND tenant_id = ?",
            (harness.tenant_id.replace("-", ""),),
        )
    assert count == 0

    # Группа с этим ключом не от bootstrap (заведённая до запрета) прав не даёт.
    harness.execute(
        "INSERT INTO groups (id, tenant_id, key, name, source, status, created_at) "
        "VALUES (?, ?, 'fleet-admins', 'fleet-admins', 'federated', 'active', "
        "CURRENT_TIMESTAMP)",
        uuid.uuid4().hex,
        harness.tenant_id.replace("-", ""),
    )
    still_refused = harness.exchange(
        subject="member", scopes=["fleet:admin"], groups=[FLEET_UPSTREAM]
    )
    assert still_refused.status_code == 403
    assert still_refused.json()["detail"] == "scope_not_allowed"


def test_people_admin_group_does_not_grant_fleet_admin(harness: Harness) -> None:
    harness.tenant("tenant-b", groups=("fleet-admins", "people-admins"))

    people_admin = harness.exchange(
        subject="people-admin", scopes=["fleet:admin"], groups=[PEOPLE_UPSTREAM]
    )

    assert people_admin.status_code == 403
    assert people_admin.json()["detail"] == "scope_not_allowed"


def test_pat_never_carries_fleet_admin(harness: Harness) -> None:
    first = harness.exchange(subject="member", scopes=["fleet:read"], groups=[FLEET_UPSTREAM])
    human_id = first.json()["principalId"]
    context = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{human_id}/authentication-contexts",
        headers=BOOTSTRAP,
        json={"issuer": harness.idp.issuer, "acr": "1", "amr": ["pwd"]},
    )
    assert context.status_code == 201, context.text
    pat = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{human_id}/platform-access-tokens",
        headers={**BOOTSTRAP, "Idempotency-Key": str(uuid.uuid4())},
        json={"name": "cli", "audiences": ["fleet"], "scopeCeiling": ["fleet:admin", "fleet:read"]},
    )
    assert pat.status_code == 201, pat.text

    explicit = harness.client.post(
        "/api/v1/platform-access-tokens:exchange",
        json={"token": pat.json()["token"], "audience": "fleet", "scopes": ["fleet:admin"]},
    )
    implicit = harness.client.post(
        "/api/v1/platform-access-tokens:exchange",
        json={"token": pat.json()["token"], "audience": "fleet", "scopes": []},
    )

    # Даже член группы: PAT живёт неделями и authority администратора не переносит.
    assert explicit.status_code == 403
    assert explicit.json()["detail"] == "scope_not_allowed"
    assert implicit.status_code == 200, implicit.text
    assert implicit.json()["scope"] == ["fleet:read"]
    assert claims(implicit)["scope_ceiling"] == ["fleet:read"]


def test_service_account_gets_fleet_admin_only_from_its_ceiling_on_request(
    harness: Harness,
) -> None:
    """Client credentials: потолок service account вписывает bootstrap (ADR-0003, п. 5)."""

    def service_account(ceiling: list[str]) -> dict[str, str]:
        created = harness.client.post(
            f"/api/v1/tenants/{harness.tenant_id}/service-accounts",
            headers=BOOTSTRAP,
            json={"displayName": "fleet operator", "audiences": ["fleet"], "scopeCeiling": ceiling},
        )
        assert created.status_code == 201, created.text
        return created.json()

    def exchange(account: dict[str, str], scopes: list[str]):
        return harness.client.post(
            "/api/v1/tokens/exchange",
            json={
                "clientId": account["clientId"],
                "clientSecret": account["clientSecret"],
                "audience": "fleet",
                "scopes": scopes,
            },
        )

    operator = service_account(["fleet:admin", "fleet:read"])
    reader = service_account(["fleet:read"])

    granted = exchange(operator, ["fleet:admin"])
    refused = exchange(reader, ["fleet:admin"])

    # Групп для service account нет: явный потолок от bootstrap — то же решение
    # администратора, что и членство в группе.
    assert granted.status_code == 200, granted.text
    assert claims(granted)["scope"] == ["fleet:admin"]
    assert refused.status_code == 403
    assert refused.json()["detail"] == "scope_not_allowed"


def test_people_admin_cannot_link_identity_to_fleet_admin(harness: Harness) -> None:
    """Identity к члену `fleet-admins` дала бы вызывающему вход с `fleet:admin`."""

    harness.tenant("tenant-b", groups=("fleet-admins", "people-admins"))
    admin = harness.exchange(
        subject="people-admin", scopes=["iam:people"], groups=[PEOPLE_UPSTREAM], audience="iam"
    )
    assert admin.status_code == 200, admin.text
    headers = {"Authorization": f"Bearer {admin.json()['accessToken']}"}
    person = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/principals",
        headers=BOOTSTRAP,
        json={"kind": "human", "displayName": "Fleet operator"},
    ).json()["id"]
    harness.add_member("fleet-admins", person)

    response = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{person}/external-identities",
        headers=headers,
        json={"issuer": harness.idp.issuer, "subject": "attacker"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "people_admin_protected"
    [denied] = [row for row in harness.audit("external_identities.link") if row[1] == "denied"]
    assert denied[2] == "group:fleet-admins"


def test_registry_keeps_builtin_and_people_scopes() -> None:
    settings = Settings(
        privileged_scopes={"fleet:admin": "platform-admins", "billing:admin": "billing-admins"},
        people_admin_group="platform-admins",
    )

    assert settings.privileged_scope_groups() == {
        "fleet:admin": "platform-admins",
        "billing:admin": "billing-admins",
        "iam:people": "platform-admins",
    }
    assert Settings().privileged_scope_groups() == {
        "fleet:admin": "fleet-admins",
        "iam:people": "people-admins",
    }
    assert Settings().privileged_group_keys() == {"fleet-admins", "people-admins"}


def test_registry_is_read_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_PRIVILEGED_SCOPES", '{"billing:admin": "billing-admins"}')

    assert Settings().privileged_scope_groups()["billing:admin"] == "billing-admins"
    assert Settings().privileged_scope_groups()["fleet:admin"] == "fleet-admins"
