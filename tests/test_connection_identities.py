"""Identity подключений и scope `iam:identities.link` (ADR-0004, п. 3–6; I015).

Приёмка: агент со `iam:identities.link` на issuer входа (Keycloak, Telegram) и
на подключение чужого tenant'а — 403, на issuer подключения своего tenant'а —
201; уникальность пары `(issuer, subject)` глобальная. Снятие сопоставления —
только identity подключения; список по issuer — страницами; администратор
людей сопоставляет без правил онбординга, но не себя. Префикс `connection:`
зарезервирован: provider с таким issuer не заводится, миграция его не пропустит.
"""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any

import jwt
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from conftest import FakeFetcher, FakeIdentityProvider
from iam_service.app import create_app
from iam_service.config import Settings
from test_people import BOOTSTRAP, ISSUER, Harness, signing_key_pem
from test_people_by_email import LINK_SCOPE, allow_link_scope, connector, controller, federate

KEY = "crm-main"


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


def issuer_of(tenant_id: str, key: str = KEY) -> str:
    return f"connection:{tenant_id}:{key}"


def person(harness: Harness, subject: str = "anna") -> str:
    """Человек, уже входящий через IdP: сопоставляемые люди как раз такие."""

    return federate(harness, subject, {})["principalId"]


def unlink(harness: Harness, headers: dict[str, str], principal_id: str, identity_id: str):
    return harness.client.delete(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{principal_id}"
        f"/external-identities/{identity_id}",
        headers=headers,
    )


def find(harness: Harness, headers: dict[str, str], **params: Any):
    return harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/external-identities",
        params=params,
        headers=headers,
    )


def events(harness: Harness, type_: str) -> list[dict[str, Any]]:
    rows = harness.client.get("/api/v1/events", headers=BOOTSTRAP).json()["items"]
    return [row["payload"] for row in rows if row["type"] == type_]


def sources(harness: Harness) -> dict[str, str]:
    with sqlite3.connect(harness.database_path) as connection:
        return dict(connection.execute("SELECT subject, source FROM external_identities"))


# --- агент: свой issuer подключения ----------------------------------------


def test_agent_links_user_of_own_connection(harness: Harness) -> None:
    anna = person(harness)
    agent = connector(harness, [LINK_SCOPE])
    issuer = issuer_of(harness.tenant_id)

    linked = harness.link(agent["headers"], anna, subject="8123", issuer=issuer)

    assert linked.status_code == 201, linked.text
    assert linked.json()["principal_id"] == anna
    assert linked.json()["issuer"] == issuer
    assert linked.json()["status"] == "active"
    # Источник выводится из issuer; правила онбординга не мешают: у Анны уже
    # есть identity входа.
    assert sources(harness)["8123"] == "connection"
    [event] = [e for e in events(harness, "external_identity.linked") if e["source"] != "federated"]
    assert event == {
        "externalIdentityId": linked.json()["id"],
        "principalId": anna,
        "source": "connection",
        "issuer": issuer,
    }
    [audit] = [row for row in harness.audit("external_identities.link") if row[1] == "allowed"]
    assert audit[0] == agent["agent_id"]
    assert audit[2] == f"issuer:{issuer} scope:{LINK_SCOPE} pat:{agent['credential_id']}"


@pytest.mark.parametrize(
    "issuer",
    [
        pytest.param("{idp}", id="keycloak-login"),
        pytest.param("iam:channel:telegram:{tenant}", id="telegram-login"),
        pytest.param("connection:{other}:crm-main", id="foreign-tenant-connection"),
        pytest.param("connection:{tenant_upper}:crm-main", id="non-canonical-tenant"),
        pytest.param("crm-main", id="arbitrary-string"),
    ],
)
def test_agent_is_refused_any_issuer_but_own_connection(harness: Harness, issuer: str) -> None:
    anna = person(harness)
    other = harness.tenant("tenant-b")
    agent = connector(harness, [LINK_SCOPE])
    issuer = issuer.format(
        idp=harness.idp.issuer,
        tenant=harness.tenant_id,
        tenant_upper=harness.tenant_id.upper(),
        other=other,
    )

    linked = harness.link(agent["headers"], anna, subject="8123", issuer=issuer)
    listed = find(harness, agent["headers"], issuer=issuer)
    exact = find(harness, agent["headers"], issuer=issuer, subject="anna")

    for response in (linked, listed, exact):
        assert response.status_code == 403, response.text
        assert response.json()["detail"] == "issuer_not_allowed"
    assert "8123" not in sources(harness)
    assert harness.denials("external_identities.link") == [
        (agent["agent_id"], "principal", f"issuer:{issuer}")
    ]
    assert (
        harness.denials("external_identities.find")
        == [(agent["agent_id"], "principal", f"issuer:{issuer}")] * 2
    )


def test_agent_issuer_refusal_comes_before_target_checks(harness: Harness) -> None:
    """Чужое пространство имён агенту отвечает только отказом — даже о несуществующей цели."""

    agent = connector(harness, [LINK_SCOPE])

    response = harness.link(
        agent["headers"], str(uuid.uuid4()), subject="8123", issuer=harness.idp.issuer
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "issuer_not_allowed"


def test_agent_of_other_tenant_path_is_refused(harness: Harness) -> None:
    agent = connector(harness, [LINK_SCOPE])
    other = harness.tenant("tenant-b")

    response = harness.client.post(
        f"/api/v1/tenants/{other}/principals/{uuid.uuid4()}/external-identities",
        headers=agent["headers"],
        json={"issuer": issuer_of(other), "subject": "8123"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_mismatch"


@pytest.mark.parametrize("key", ["", "a:b", "CRM", "crm main", "x" * 201])
def test_malformed_connection_issuer_is_refused(harness: Harness, key: str) -> None:
    anna = person(harness)
    agent = connector(harness, [LINK_SCOPE])

    by_agent = harness.link(agent["headers"], anna, issuer=issuer_of(harness.tenant_id, key))
    by_bootstrap = harness.link(BOOTSTRAP, anna, issuer=issuer_of(harness.tenant_id, key))

    for response in (by_agent, by_bootstrap):
        assert response.status_code == 422, response.text
        assert response.json()["detail"] == "invalid_connection_issuer"


def test_connection_target_must_be_active_human(harness: Harness) -> None:
    anna = person(harness)
    robot = harness.bootstrap_principal("agent")
    agent = connector(harness, [LINK_SCOPE])
    issuer = issuer_of(harness.tenant_id)

    to_agent = harness.link(agent["headers"], robot, subject="1", issuer=issuer)
    by_bootstrap_to_agent = harness.link(BOOTSTRAP, robot, subject="1", issuer=issuer)
    assert harness.disable(BOOTSTRAP, anna).status_code == 200
    to_disabled = harness.link(agent["headers"], anna, subject="2", issuer=issuer)
    missing = harness.link(agent["headers"], str(uuid.uuid4()), subject="3", issuer=issuer)
    # Bootstrap сопоставить отключённого может.
    by_bootstrap = harness.link(BOOTSTRAP, anna, subject="2", issuer=issuer)

    assert to_agent.status_code == by_bootstrap_to_agent.status_code == 422
    assert to_agent.json()["detail"] == "human_principal_required"
    assert to_disabled.status_code == 409
    assert to_disabled.json()["detail"] == "principal_not_active"
    assert missing.status_code == 404
    assert missing.json()["detail"] == "principal_not_found"
    assert by_bootstrap.status_code == 201, by_bootstrap.text


def test_pair_is_globally_unique_and_freed_by_unlink(harness: Harness) -> None:
    anna, boris = person(harness, "anna"), person(harness, "boris")
    agent = connector(harness, [LINK_SCOPE])
    issuer = issuer_of(harness.tenant_id)

    first = harness.link(agent["headers"], anna, subject="8123", issuer=issuer)
    taken = harness.link(agent["headers"], boris, subject="8123", issuer=issuer)
    # Пара занята и для bootstrap: уникальность не зависит от вызывающего.
    taken_by_bootstrap = harness.link(BOOTSTRAP, boris, subject="8123", issuer=issuer)

    assert first.status_code == 201, first.text
    assert taken.status_code == taken_by_bootstrap.status_code == 409
    assert taken.json()["detail"] == "external_identity_exists"

    removed = unlink(harness, agent["headers"], anna, first.json()["id"])
    relinked = harness.link(agent["headers"], boris, subject="8123", issuer=issuer)

    assert removed.status_code == 204, removed.text
    assert relinked.status_code == 201, relinked.text
    assert relinked.json()["principal_id"] == boris


def test_same_subject_in_other_connection_is_another_identity(harness: Harness) -> None:
    anna = person(harness)
    agent = connector(harness, [LINK_SCOPE])

    first = harness.link(agent["headers"], anna, "8123", issuer_of(harness.tenant_id, "crm-a"))
    second = harness.link(agent["headers"], anna, "8123", issuer_of(harness.tenant_id, "crm-b"))

    assert first.status_code == second.status_code == 201


# --- снятие сопоставления ---------------------------------------------------


def test_agent_unlinks_connection_identity(harness: Harness) -> None:
    anna = person(harness)
    agent = connector(harness, [LINK_SCOPE])
    issuer = issuer_of(harness.tenant_id)
    linked = harness.link(agent["headers"], anna, subject="8123", issuer=issuer).json()

    wrong_principal = unlink(harness, agent["headers"], person(harness, "boris"), linked["id"])
    removed = unlink(harness, agent["headers"], anna, linked["id"])
    again = unlink(harness, agent["headers"], anna, linked["id"])

    assert wrong_principal.status_code == 404
    assert wrong_principal.json()["detail"] == "external_identity_not_found"
    assert removed.status_code == 204, removed.text
    assert again.status_code == 404
    assert "8123" not in sources(harness)
    assert events(harness, "external_identity.unlinked") == [
        {
            "externalIdentityId": linked["id"],
            "principalId": anna,
            "source": "connection",
            "issuer": issuer,
        }
    ]
    [audit] = [row for row in harness.audit("external_identities.unlink") if row[1] == "allowed"]
    assert audit == (
        agent["agent_id"],
        "allowed",
        f"issuer:{issuer} scope:{LINK_SCOPE} pat:{agent['credential_id']}",
    )


def test_login_identity_is_not_unlinked(harness: Harness) -> None:
    anna = person(harness)
    agent = connector(harness, [LINK_SCOPE])
    [login] = find(harness, BOOTSTRAP, issuer=harness.idp.issuer, subject="anna").json()["items"]

    by_agent = unlink(harness, agent["headers"], anna, login["id"])
    by_bootstrap = unlink(harness, BOOTSTRAP, anna, login["id"])

    assert by_agent.status_code == 403
    assert by_agent.json()["detail"] == "issuer_not_allowed"
    assert by_bootstrap.status_code == 422
    assert by_bootstrap.json()["detail"] == "connection_identity_required"
    assert sources(harness)["anna"] == "federated"
    assert harness.denials("external_identities.unlink") == [
        (agent["agent_id"], "principal", f"issuer:{harness.idp.issuer}"),
        ("bootstrap", "principal", "source:federated"),
    ]


def test_foreign_connection_identity_is_not_unlinked_by_agent(harness: Harness) -> None:
    """Identity чужого подключения в своём tenant'е (занесена bootstrap) агенту не отдаётся."""

    anna = person(harness)
    other = harness.tenant("tenant-b")
    agent = connector(harness, [LINK_SCOPE])
    # Bootstrap тоже не привяжет чужой tenant — только через базу в обход API.
    refused = harness.link(BOOTSTRAP, anna, subject="8123", issuer=issuer_of(other))
    assert refused.status_code == 422
    assert refused.json()["detail"] == "issuer_tenant_mismatch"
    identity_id = uuid.uuid4()
    harness.execute(
        "INSERT INTO external_identities (id, principal_id, issuer, subject, status, source, "
        "created_at) VALUES (?, ?, ?, '8123', 'active', 'connection', CURRENT_TIMESTAMP)",
        identity_id.hex,
        uuid.UUID(anna).hex,
        issuer_of(other),
    )

    response = unlink(harness, agent["headers"], anna, str(identity_id))

    assert response.status_code == 403
    assert response.json()["detail"] == "issuer_not_allowed"


def test_foreign_connection_identity_is_not_unlinked_by_bootstrap_or_people_admin(
    harness: Harness,
) -> None:
    """Tenant issuer'а — tenant пути и на снятии, для любого вызывающего (ADR-0004, п. 4.2)."""

    anna = person(harness)
    headers, _ = harness.federate()
    other = harness.tenant("tenant-b")
    identity_id = uuid.uuid4()
    harness.execute(
        "INSERT INTO external_identities (id, principal_id, issuer, subject, status, source, "
        "created_at) VALUES (?, ?, ?, '8123', 'active', 'connection', CURRENT_TIMESTAMP)",
        identity_id.hex,
        uuid.UUID(anna).hex,
        issuer_of(other),
    )

    by_bootstrap = unlink(harness, BOOTSTRAP, anna, str(identity_id))
    by_admin = unlink(harness, headers, anna, str(identity_id))

    assert by_bootstrap.status_code == 422
    assert by_bootstrap.json()["detail"] == "issuer_tenant_mismatch"
    assert by_admin.status_code == 422
    assert by_admin.json()["detail"] == "issuer_tenant_mismatch"
    assert sources(harness)["8123"] == "connection"
    assert events(harness, "external_identity.unlinked") == []
    assert [row[2] for row in harness.denials("external_identities.unlink")] == [
        f"issuer:{issuer_of(other)}",
        f"issuer:{issuer_of(other)}",
    ]


def test_agent_issuer_refusal_on_unlink_comes_before_not_found(harness: Harness) -> None:
    """Чужое пространство имён агенту — 403, даже если identity не принадлежит Principal пути."""

    anna = person(harness)
    boris = person(harness, "boris")
    agent = connector(harness, [LINK_SCOPE])
    [login] = find(harness, BOOTSTRAP, issuer=harness.idp.issuer, subject="boris").json()["items"]
    own = harness.link(agent["headers"], boris, "8123", issuer_of(harness.tenant_id)).json()

    foreign = unlink(harness, agent["headers"], anna, login["id"])
    own_elsewhere = unlink(harness, agent["headers"], anna, own["id"])
    missing = unlink(harness, agent["headers"], anna, str(uuid.uuid4()))

    assert foreign.status_code == 403
    assert foreign.json()["detail"] == "issuer_not_allowed"
    # Свой issuer проходит проверку и получает 404 за чужого Principal.
    assert own_elsewhere.status_code == 404
    assert own_elsewhere.json()["detail"] == "external_identity_not_found"
    assert missing.status_code == 404
    assert sources(harness)["boris"] == "federated"
    assert sources(harness)["8123"] == "connection"


# --- список по issuer ---------------------------------------------------------


def test_agent_lists_connection_identities_by_pages(harness: Harness) -> None:
    agent = connector(harness, [LINK_SCOPE])
    issuer = issuer_of(harness.tenant_id)
    people = [person(harness, f"user-{index}") for index in range(3)]
    linked = sorted(
        harness.link(agent["headers"], principal, subject=f"crm-{index}", issuer=issuer).json()[
            "id"
        ]
        for index, principal in enumerate(people)
    )
    harness.link(agent["headers"], people[0], "crm-x", issuer_of(harness.tenant_id, "other"))

    first = find(harness, agent["headers"], issuer=issuer, limit=2)
    second = find(
        harness, agent["headers"], issuer=issuer, limit=2, after=first.json()["next_after"]
    )
    exact = find(harness, agent["headers"], issuer=issuer, subject="crm-1")
    too_many = find(harness, agent["headers"], issuer=issuer, limit=201)

    assert first.status_code == 200, first.text
    assert [item["id"] for item in first.json()["items"]] == linked[:2]
    assert first.json()["next_after"] == linked[1]
    assert [item["id"] for item in second.json()["items"]] == linked[2:]
    assert second.json()["next_after"] is None
    assert [item["subject"] for item in exact.json()["items"]] == ["crm-1"]
    assert exact.json()["next_after"] is None
    assert too_many.status_code == 422
    # Почты в элементе нет (ADR-0004, п. 1).
    assert set(first.json()["items"][0]) == {"id", "principal_id", "issuer", "subject", "status"}


def test_list_by_issuer_is_scoped_to_tenant(harness: Harness) -> None:
    other = harness.tenant("tenant-b")
    agent = connector(harness, [LINK_SCOPE])
    anna = person(harness)
    issuer = issuer_of(harness.tenant_id)
    assert harness.link(agent["headers"], anna, "8123", issuer).status_code == 201

    foreign = harness.client.get(
        f"/api/v1/tenants/{other}/external-identities",
        params={"issuer": issuer},
        headers=BOOTSTRAP,
    )

    assert foreign.status_code == 200
    assert foreign.json() == {"items": [], "next_after": None}


# --- администратор людей и bootstrap ----------------------------------------


def test_people_admin_links_without_onboarding_rules_but_not_self(harness: Harness) -> None:
    anna = person(harness)
    headers, admin = harness.federate()
    issuer = issuer_of(harness.tenant_id)
    other = harness.tenant("tenant-b")

    linked = harness.link(headers, anna, subject="8123", issuer=issuer)
    self_link = harness.link(headers, admin["principalId"], subject="9000", issuer=issuer)
    foreign = harness.link(headers, anna, subject="8124", issuer=issuer_of(other))
    listed = find(harness, headers, issuer=issuer)
    login_list = find(harness, headers, issuer=harness.idp.issuer)

    # У Анны есть identity входа — привязка IdP ей запрещена, подключения — нет.
    assert linked.status_code == 201, linked.text
    assert self_link.status_code == 403
    assert self_link.json()["detail"] == "self_link_forbidden"
    assert foreign.status_code == 422
    assert foreign.json()["detail"] == "issuer_tenant_mismatch"
    assert [item["subject"] for item in listed.json()["items"]] == ["8123"]
    # Администратору людей — любой issuer.
    assert {item["subject"] for item in login_list.json()["items"]} == {"anna", "admin"}

    # Себя не отвязать; bootstrap сопоставляет администратора, другой — снимает.
    own = harness.link(BOOTSTRAP, admin["principalId"], subject="9000", issuer=issuer)
    assert own.status_code == 201, own.text
    refused = unlink(harness, headers, admin["principalId"], own.json()["id"])
    assert refused.status_code == 403
    assert refused.json()["detail"] == "self_link_forbidden"
    assert unlink(harness, headers, anna, linked.json()["id"]).status_code == 204


def test_people_admin_login_identity_rules_are_unchanged(harness: Harness) -> None:
    anna = person(harness)
    headers, _ = harness.federate()

    response = harness.link(headers, anna, subject="second-login")

    assert response.status_code == 409
    assert response.json()["detail"] == "principal_has_identity"


def test_connection_identity_does_not_block_onboarding_link(harness: Harness) -> None:
    """Человек, сопоставленный только с CRM, — всё ещё новичок: вход ему привязывают."""

    newcomer = harness.bootstrap_principal("human")
    agent = connector(harness, [LINK_SCOPE])
    headers, _ = harness.federate()
    mapped = harness.link(agent["headers"], newcomer, "8123", issuer_of(harness.tenant_id))
    assert mapped.status_code == 201, mapped.text

    login = harness.link(headers, newcomer, subject="newcomer")
    second = harness.link(headers, newcomer, subject="newcomer-2")

    assert login.status_code == 201, login.text
    assert sources(harness)["newcomer"] == "manual"
    # Identity входа уже есть — дальше прежние правила онбординга.
    assert second.status_code == 409
    assert second.json()["detail"] == "principal_has_identity"


def test_manual_link_event_names_source_and_issuer(harness: Harness) -> None:
    newcomer = harness.bootstrap_principal("human")

    linked = harness.link(BOOTSTRAP, newcomer, subject="newcomer")

    assert linked.status_code == 201, linked.text
    assert sources(harness)["newcomer"] == "manual"
    [event] = [e for e in events(harness, "external_identity.linked") if e["source"] == "manual"]
    assert event["issuer"] == harness.idp.issuer
    [audit] = harness.audit("external_identities.link")
    assert audit == ("bootstrap", "allowed", f"issuer:{harness.idp.issuer}")


def test_federated_link_event_names_source_and_issuer(harness: Harness) -> None:
    anna = person(harness)

    [event] = events(harness, "external_identity.linked")

    assert event["principalId"] == anna
    assert event["source"] == "federated"
    assert event["issuer"] == harness.idp.issuer
    assert event["identityProvider"] == "keycloak"


# --- кто держит scope ---------------------------------------------------------


def test_non_agents_with_link_scope_get_nothing(harness: Harness) -> None:
    anna = person(harness)
    allow_link_scope(harness)
    human, _ = harness.federate(subject="boris", scopes=[LINK_SCOPE], admin=False)
    account, _ = controller(harness, [LINK_SCOPE])
    issuer = issuer_of(harness.tenant_id)

    by_human = harness.link(human, anna, "8123", issuer)
    by_account = harness.link(account, anna, "8123", issuer)

    assert by_human.status_code == 403
    assert by_human.json()["detail"] == "scope_not_granted"
    assert by_account.status_code == 403
    assert by_account.json()["detail"] == "agent_required"


def test_agent_without_link_scope_is_refused(harness: Harness) -> None:
    anna = person(harness)
    agent = connector(harness, ["iam:channel-links"])

    response = harness.link(agent["headers"], anna, "8123", issuer_of(harness.tenant_id))

    assert response.status_code == 403
    assert response.json()["detail"] == "scope_not_granted"


def test_revoked_pat_closes_linking(harness: Harness) -> None:
    anna = person(harness)
    agent = connector(harness, [LINK_SCOPE])
    revoked = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/agents/{agent['agent_id']}"
        f"/platform-access-tokens/{agent['credential_id']}:revoke",
        headers=agent["owner"],
    )
    assert revoked.status_code == 204, revoked.text

    response = harness.link(agent["headers"], anna, "8123", issuer_of(harness.tenant_id))

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_token"


def test_agent_gets_nothing_else_of_people_routes(harness: Harness) -> None:
    anna = person(harness)
    agent = connector(harness, [LINK_SCOPE])
    base = f"/api/v1/tenants/{harness.tenant_id}/principals"
    headers = {**agent["headers"], "Idempotency-Key": str(uuid.uuid4())}

    responses = [
        harness.client.post(base, headers=headers, json={"kind": "human", "displayName": "x"}),
        harness.client.get(base, headers=headers),
        harness.client.get(f"{base}/{anna}", headers=headers),
        harness.client.get(f"{base}/{anna}/external-identities", headers=headers),
        harness.client.post(f"{base}/{anna}:disable", headers=headers),
        harness.client.post(f"{base}/{anna}:enable", headers=headers),
    ]

    for response in responses:
        assert response.status_code == 403, response.text
        assert response.json()["detail"] == "human_required"


def test_exchange_delivers_link_scope_to_agent(harness: Harness) -> None:
    """Scope в allowed scopes audience `iam`: PAT агента его приносит, он не привилегированный."""

    agent = connector(harness, [LINK_SCOPE])
    token = agent["headers"]["Authorization"].removeprefix("Bearer ")

    claims = jwt.decode(token, options={"verify_signature": False})

    assert claims["aud"] == "iam"
    assert claims["principal_type"] == "agent"
    assert claims["scope"] == [LINK_SCOPE]


# --- резерв префикса `connection:` -----------------------------------------


def test_identity_provider_cannot_take_connection_prefix(harness: Harness) -> None:
    response = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/identity-providers",
        headers=BOOTSTRAP,
        json={"key": "sneaky", "issuer": issuer_of(harness.tenant_id), "audience": "iam"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "invalid_issuer"


def _migrated(tmp_path, revision: str) -> tuple[Config, Any]:
    database_path = tmp_path / "migration.db"
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{database_path}")
    command.upgrade(config, revision)
    return config, database_path


def test_migration_refuses_provider_with_reserved_prefix(tmp_path) -> None:
    config, database_path = _migrated(tmp_path, "0009_identity_email")
    tenant_id = uuid.uuid4().hex
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "INSERT INTO tenants (id, slug, name, status, created_at) "
            "VALUES (?, 't', 't', 'active', CURRENT_TIMESTAMP)",
            (tenant_id,),
        )
        connection.execute(
            "INSERT INTO identity_providers (id, tenant_id, key, issuer, audience, jwks_uri, "
            "subject_claim, external_id_claim, group_claim, group_mappings, "
            "required_acr_values, required_amr_values, lifecycle_profile, status, "
            "jwks_cache_ttl_seconds, jwks_stale_grace_seconds, created_at) "
            "VALUES (?, ?, 'sneaky', 'connection:x:y', 'iam', '', 'sub', 'sub', 'groups', "
            "'{}', '[]', '[]', 'read_only', 'active', 300, 900, "
            "CURRENT_TIMESTAMP)",
            (uuid.uuid4().hex, tenant_id),
        )

    with pytest.raises(RuntimeError, match="sneaky"):
        command.upgrade(config, "head")


def test_migration_adds_connection_source_and_downgrade_drops_it(tmp_path) -> None:
    config, database_path = _migrated(tmp_path, "head")
    principal_id = uuid.uuid4().hex
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "INSERT INTO principals (id, kind, display_name, status, created_at) "
            "VALUES (?, 'human', 'Anna', 'active', CURRENT_TIMESTAMP)",
            (principal_id,),
        )
        connection.execute(
            "INSERT INTO external_identities (id, principal_id, issuer, subject, status, "
            "source, created_at) VALUES (?, ?, 'connection:t:k', '8123', 'active', "
            "'connection', CURRENT_TIMESTAMP)",
            (uuid.uuid4().hex, principal_id),
        )

    command.downgrade(config, "0009_identity_email")
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM external_identities").fetchone() == (0,)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO external_identities (id, principal_id, issuer, subject, status, "
                "source, created_at) VALUES (?, ?, 'connection:t:k', '1', 'active', "
                "'connection', CURRENT_TIMESTAMP)",
                (uuid.uuid4().hex, principal_id),
            )
