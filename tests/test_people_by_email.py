"""Почта федеративной identity и поиск человека по почте (ADR-0004, п. 1–2; I014).

Приёмка: неподтверждённая почта не сохраняется (и очищает прежнюю); поиск не
возвращает агентов и отключённых; два совпадения возвращаются оба — решение
за вызывающим; без scope — 403. Допуск: bootstrap, человек со `iam:people`,
агент со `iam:identities.link` (token обмена его PAT). Адрес не попадает ни в
ответ, ни в audit, ни в access log uvicorn.
"""

from __future__ import annotations

import logging
import socket
import sqlite3
import threading
import time
import uuid
from typing import Any

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from conftest import FakeFetcher, FakeIdentityProvider
from iam_service.access_log import ACCESS_LOGGER, EmailRedactingFilter, redact_query
from iam_service.app import create_app
from iam_service.config import Settings
from iam_service.tokens import TokenIssuer
from test_people import BOOTSTRAP, ISSUER, Harness, signing_key_pem

LINK_SCOPE = "iam:identities.link"


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


def federate(
    harness: Harness, subject: str, claims: dict[str, Any], *, route: str = "exchange"
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "identityProvider": "keycloak",
        "token": harness.idp.token(subject=subject, claims={"acr": "1", **claims}),
    }
    if route == "exchange":
        body.update({"audience": "iam", "scopes": []})
    response = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/federation:{route}", json=body
    )
    assert response.status_code == 200, response.text
    return response.json()


def verified(email: str) -> dict[str, Any]:
    return {"email": email, "email_verified": True}


def stored_email(harness: Harness, subject: str) -> str | None:
    with sqlite3.connect(harness.database_path) as connection:
        (email,) = connection.execute(
            "SELECT email FROM external_identities WHERE subject = ?", (subject,)
        ).fetchone()
    return email


def search(harness: Harness, email: str, headers: dict[str, str] | None = None):
    return harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals:by-email",
        params={"email": email},
        headers=BOOTSTRAP if headers is None else headers,
    )


def found(harness: Harness, email: str, headers: dict[str, str] | None = None) -> list[str]:
    response = search(harness, email, headers)
    assert response.status_code == 200, response.text
    return [item["id"] for item in response.json()["items"]]


def allow_link_scope(harness: Harness) -> None:
    """Bootstrap добавляет scope в allowed scopes audience `iam` (ADR-0004, п. 5)."""

    response = harness.client.patch(
        f"/api/v1/tenants/{harness.tenant_id}/audiences/iam",
        headers=BOOTSTRAP,
        json={"allowedScopes": ["iam:agents", "iam:channel-links", "iam:people", LINK_SCOPE]},
    )
    assert response.status_code == 200, response.text


def controller(harness: Harness, ceiling: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    account = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/service-accounts",
        headers=BOOTSTRAP,
        json={"displayName": "fleet-controller", "audiences": ["iam"], "scopeCeiling": ceiling},
    ).json()
    token = harness.client.post(
        "/api/v1/tokens/exchange",
        json={
            "clientId": account["clientId"],
            "clientSecret": account["clientSecret"],
            "audience": "iam",
            "scopes": ceiling,
        },
    )
    assert token.status_code == 200, token.text
    return {"Authorization": f"Bearer {token.json()['accessToken']}"}, account


def connector(harness: Harness, ceiling: list[str]) -> dict[str, Any]:
    """Агент-коннектор по цепочке ADR-0001: владелец выпускает PAT, агент меняет его."""

    allow_link_scope(harness)
    owner, _ = controller(harness, ["iam:agents", "iam:channel-links", LINK_SCOPE])
    agent = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/agents",
        headers=owner,
        json={"displayName": "crm connector"},
    ).json()
    issued = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/agents/{agent['id']}/platform-access-tokens",
        headers={**owner, "Idempotency-Key": str(uuid.uuid4())},
        json={
            "name": "connector",
            "audiences": ["iam"],
            "scopeCeiling": ceiling,
            "expiresInSeconds": 3600,
        },
    )
    assert issued.status_code == 201, issued.text
    exchanged = harness.client.post(
        "/api/v1/platform-access-tokens:exchange",
        json={"token": issued.json()["token"], "audience": "iam", "scopes": []},
    )
    assert exchanged.status_code == 200, exchanged.text
    return {
        "agent_id": agent["id"],
        "owner": owner,
        "credential_id": issued.json()["credential"]["id"],
        "headers": {"Authorization": f"Bearer {exchanged.json()['accessToken']}"},
    }


# --- почта на identity ------------------------------------------------------


@pytest.mark.parametrize("route", ["exchange", "authenticate"])
def test_verified_email_is_stored_normalized(harness: Harness, route: str) -> None:
    person = federate(harness, "anna", verified("  Anna.Smith@Example.COM "), route=route)

    assert stored_email(harness, "anna") == "anna.smith@example.com"
    assert found(harness, "ANNA.smith@example.com ") == [person["principalId"]]


@pytest.mark.parametrize(
    "claims",
    [
        {"email": "anna@example.com"},
        {"email": "anna@example.com", "email_verified": False},
        {"email": "anna@example.com", "email_verified": "true"},
        {"email": "anna@example.com", "email_verified": 1},
        {"email_verified": True},
        {"email": "not-an-address", "email_verified": True},
        {"email": "a@b@example.com", "email_verified": True},
        {"email": "@example.com", "email_verified": True},
        {"email": ["anna@example.com"], "email_verified": True},
    ],
)
def test_unverified_or_invalid_email_is_not_stored(harness: Harness, claims) -> None:
    federate(harness, "anna", claims)

    assert stored_email(harness, "anna") is None
    assert found(harness, "anna@example.com") == []


def test_email_follows_current_idp_token(harness: Harness) -> None:
    person = federate(harness, "anna", verified("anna@example.com"))
    federate(harness, "anna", verified("anna.smith@example.com"))

    assert found(harness, "anna@example.com") == []
    assert found(harness, "anna.smith@example.com") == [person["principalId"]]

    # Почта, переставшая быть подтверждённой, сразу перестаёт находить человека.
    federate(harness, "anna", {"email": "anna.smith@example.com", "email_verified": False})

    assert stored_email(harness, "anna") is None
    assert found(harness, "anna.smith@example.com") == []


def test_email_is_not_readable(harness: Harness) -> None:
    person = federate(harness, "anna", verified("anna@example.com"))

    identities = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{person['principalId']}"
        "/external-identities",
        headers=BOOTSTRAP,
    )
    principal = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{person['principalId']}",
        headers=BOOTSTRAP,
    )
    events = harness.client.get("/api/v1/events", headers=BOOTSTRAP)

    assert identities.status_code == 200
    for response in (identities, principal, events):
        assert "anna@example.com" not in response.text
    with sqlite3.connect(harness.database_path) as connection:
        audit = " ".join(str(row) for row in connection.execute("SELECT * FROM audit_events"))
    assert "anna@example.com" not in audit


# --- поиск ------------------------------------------------------------------


def test_two_matches_are_both_returned(harness: Harness) -> None:
    first = federate(harness, "anna", verified("shared@example.com"))
    second = federate(harness, "anna-2", verified("Shared@Example.com"))

    assert found(harness, "shared@example.com") == sorted(
        [first["principalId"], second["principalId"]]
    )


def test_search_returns_only_active_humans(harness: Harness) -> None:
    human = federate(harness, "anna", verified("anna@example.com"))
    disabled = federate(harness, "boris", verified("boris@example.com"))
    paused = federate(harness, "vera", verified("vera@example.com"))
    agent = federate(harness, "robot", verified("robot@example.com"))
    assert harness.disable(BOOTSTRAP, disabled["principalId"]).status_code == 200
    harness.execute(
        "UPDATE principals SET status = 'paused' WHERE id = ?", uuid.UUID(paused["principalId"]).hex
    )
    # Identity с подтверждённой почтой у Principal не-человека: поиск его не отдаёт.
    harness.execute(
        "UPDATE principals SET kind = 'agent' WHERE id = ?", uuid.UUID(agent["principalId"]).hex
    )

    assert found(harness, "anna@example.com") == [human["principalId"]]
    assert found(harness, "boris@example.com") == []
    assert found(harness, "vera@example.com") == []
    assert found(harness, "robot@example.com") == []


def test_search_needs_active_identity_membership_and_provider(harness: Harness) -> None:
    identity_off = federate(harness, "anna", verified("anna@example.com"))
    membership_off = federate(harness, "boris", verified("boris@example.com"))
    harness.execute(
        "UPDATE external_identities SET status = 'disabled' WHERE principal_id = ?",
        uuid.UUID(identity_off["principalId"]).hex,
    )
    harness.execute(
        "UPDATE tenant_memberships SET status = 'disabled' WHERE principal_id = ?",
        uuid.UUID(membership_off["principalId"]).hex,
    )

    assert found(harness, "anna@example.com") == []
    assert found(harness, "boris@example.com") == []

    person = federate(harness, "vera", verified("vera@example.com"))
    assert found(harness, "vera@example.com") == [person["principalId"]]
    harness.execute("UPDATE identity_providers SET status = 'disabled'")

    assert found(harness, "vera@example.com") == []


def test_search_is_scoped_to_tenant(harness: Harness) -> None:
    person = federate(harness, "anna", verified("anna@example.com"))
    other = harness.tenant("tenant-b")

    response = harness.client.get(
        f"/api/v1/tenants/{other}/principals:by-email",
        params={"email": "anna@example.com"},
        headers=BOOTSTRAP,
    )

    assert response.status_code == 200
    assert response.json() == {"items": []}
    assert found(harness, "anna@example.com") == [person["principalId"]]


def test_missing_tenant_is_not_found(harness: Harness) -> None:
    response = harness.client.get(
        f"/api/v1/tenants/{uuid.uuid4()}/principals:by-email",
        params={"email": "anna@example.com"},
        headers=BOOTSTRAP,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "tenant_not_found"


@pytest.mark.parametrize(
    "email", ["ab", "no-at-sign", "a@b@c", "@example.com", "anna@", "x" * 321 + "@e.com"]
)
def test_invalid_email_is_refused_without_echo(harness: Harness, email: str) -> None:
    response = search(harness, email)

    assert response.status_code == 422
    assert response.json() == {"detail": "invalid_email"}


def test_email_is_required(harness: Harness) -> None:
    response = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/principals:by-email", headers=BOOTSTRAP
    )

    assert response.status_code == 422


def test_search_is_not_audited(harness: Harness) -> None:
    federate(harness, "anna", verified("anna@example.com"))
    with sqlite3.connect(harness.database_path) as connection:
        before = connection.execute("SELECT count(*) FROM audit_events").fetchone()

    found(harness, "anna@example.com")

    with sqlite3.connect(harness.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM audit_events").fetchone() == before


# --- допуск -----------------------------------------------------------------


def test_people_admin_finds_people(harness: Harness) -> None:
    person = federate(harness, "anna", verified("anna@example.com"))
    headers, _ = harness.federate()

    assert found(harness, "anna@example.com", headers) == [person["principalId"]]


def test_agent_with_link_scope_finds_people(harness: Harness) -> None:
    person = federate(harness, "anna", verified("anna@example.com"))
    agent = connector(harness, [LINK_SCOPE])

    assert found(harness, "anna@example.com", agent["headers"]) == [person["principalId"]]
    assert harness.denials("identities.authenticate") == []


def test_without_scope_is_forbidden(harness: Harness) -> None:
    federate(harness, "anna", verified("anna@example.com"))
    human, admin = harness.federate(scopes=["iam:channel-links"])
    agent = connector(harness, ["iam:channel-links"])

    by_human = search(harness, "anna@example.com", human)
    by_agent = search(harness, "anna@example.com", agent["headers"])
    anonymous = search(harness, "anna@example.com", {})

    assert by_human.status_code == 403
    assert by_human.json()["detail"] == "scope_not_granted"
    assert by_agent.status_code == 403
    assert by_agent.json()["detail"] == "scope_not_granted"
    assert anonymous.status_code == 401
    assert harness.audit("people.authenticate")[-1][:2] == (admin["principalId"], "denied")
    assert harness.denials("identities.authenticate") == [
        (agent["agent_id"], "principal", "scope_not_granted")
    ]


def test_human_with_link_scope_only_is_refused(harness: Harness) -> None:
    """Scope подключений человеку ничего не даёт: нужен `iam:people`."""

    allow_link_scope(harness)
    federate(harness, "anna", verified("anna@example.com"))
    headers, _ = harness.federate(scopes=[LINK_SCOPE])

    response = search(harness, "anna@example.com", headers)

    assert response.status_code == 403
    assert response.json()["detail"] == "scope_not_granted"


def test_service_account_with_link_scope_is_refused(harness: Harness) -> None:
    allow_link_scope(harness)
    headers, account = controller(harness, [LINK_SCOPE])

    response = search(harness, "anna@example.com", headers)

    assert response.status_code == 403
    assert response.json()["detail"] == "agent_required"
    assert harness.denials("identities.authenticate") == [
        (account["principalId"], "principal", "principal_type:service_account")
    ]


def test_forged_agent_token_without_pat_is_refused(harness: Harness) -> None:
    """Token агента проходит, только если его `credential_id` — PAT этого агента."""

    agent_id = harness.bootstrap_principal("agent")
    forged = _forged_link_token(harness, agent_id, str(uuid.uuid4()))

    response = search(harness, "anna@example.com", forged)

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_token"
    assert harness.denials("identities.authenticate")[-1] == (
        agent_id,
        "principal",
        "closed:credential",
    )


def test_revoked_pat_or_disabled_agent_closes_the_path(harness: Harness) -> None:
    agent = connector(harness, [LINK_SCOPE])
    assert search(harness, "anna@example.com", agent["headers"]).status_code == 200

    revoked = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/agents/{agent['agent_id']}"
        f"/platform-access-tokens/{agent['credential_id']}:revoke",
        headers=agent["owner"],
    )
    assert revoked.status_code == 204, revoked.text
    response = search(harness, "anna@example.com", agent["headers"])

    assert response.status_code == 401
    assert harness.denials("identities.authenticate")[-1][2] == "closed:credential"

    other = connector(harness, [LINK_SCOPE])
    harness.execute(
        "UPDATE principals SET status = 'disabled' WHERE id = ?",
        uuid.UUID(other["agent_id"]).hex,
    )
    response = search(harness, "anna@example.com", other["headers"])

    assert response.status_code == 401
    assert harness.denials("identities.authenticate")[-1][2] == "closed:principal"


def test_foreign_tenant_token_is_refused(harness: Harness) -> None:
    agent = connector(harness, [LINK_SCOPE])
    other = harness.tenant("tenant-b")

    response = harness.client.get(
        f"/api/v1/tenants/{other}/principals:by-email",
        params={"email": "anna@example.com"},
        headers=agent["headers"],
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_mismatch"


def test_route_is_in_openapi(harness: Harness) -> None:
    spec = harness.client.get("/openapi.json").json()
    operation = spec["paths"]["/api/v1/tenants/{tenant_id}/principals:by-email"]["get"]
    email = next(item for item in operation["parameters"] if item["name"] == "email")

    assert email["required"] is True
    assert email["schema"]["minLength"] == 3
    assert email["schema"]["maxLength"] == 320


def _forged_link_token(harness: Harness, agent_id: str, credential_id: str) -> dict[str, str]:
    token = TokenIssuer(
        issuer=harness.settings.issuer,
        private_key=harness.settings.signing_private_key,
        key_id=harness.settings.signing_key_id,
        ttl_seconds=300,
    ).issue(
        subject=uuid.UUID(agent_id),
        tenant_id=uuid.UUID(harness.tenant_id),
        audience="iam",
        scopes=[LINK_SCOPE],
        credential_id=uuid.UUID(credential_id),
        principal_type="agent",
    )
    return {"Authorization": f"Bearer {token}"}


# --- access log -------------------------------------------------------------


def test_access_log_filter_redacts_email_argument() -> None:
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        (
            "127.0.0.1:5000",
            "GET",
            "/api/v1/tenants/t/principals:by-email?x=1&EMAIL=anna%40example.com&y=2",
            "1.1",
            200,
        ),
        None,
    )

    EmailRedactingFilter().filter(record)

    assert "anna" not in record.getMessage()
    assert "EMAIL=[redacted]&y=2" in record.getMessage()
    assert len(record.args) == 5


@pytest.mark.parametrize("name", ["e%6Dail", "%65%6D%61%69%6C", "E%4DAIL", "%45mail"])
def test_access_log_filter_decodes_parameter_name(name: str) -> None:
    """Закодированное имя доходит до маршрута как `email` — и вырезается так же."""

    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:5000", "GET", f"/p?x=a%40b&{name}=anna%40example.com", "1.1", 200),
        None,
    )

    EmailRedactingFilter().filter(record)

    assert "anna" not in record.getMessage()
    assert f"?x=a%40b&{name}=[redacted] HTTP" in record.getMessage()


def test_access_log_filter_keeps_other_parameters() -> None:
    assert redact_query("/p?emails=1&x-email=2&email&y=3#email=4") == (
        "/p?emails=1&x-email=2&email&y=3#email=4"
    )
    assert redact_query("/p") == "/p"


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.INFO)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.mark.parametrize("name", ["email", "e%6Dail"])
def test_uvicorn_access_log_has_no_email(harness: Harness, name: str) -> None:
    """Живой uvicorn: после запроса к поиску адреса в записи access log нет.

    Фильтр ставит `create_app`. Обработчик вешается прямо на логгер
    `uvicorn.access`: `fileConfig` alembic в соседних тестах отключает уже
    созданные логгеры, а распространение до корня здесь не проверяется.
    """

    federate(harness, "anna", verified("anna@example.com"))
    logger = logging.getLogger(ACCESS_LOGGER)
    saved = (logger.disabled, logger.level)
    logger.filters = [item for item in logger.filters if not isinstance(item, EmailRedactingFilter)]
    app = create_app(harness.settings)
    records = _Records()
    logger.disabled = False
    logger.setLevel(logging.INFO)
    logger.addHandler(records)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_config=None, access_log=True))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        assert server.started
        response = httpx.get(
            f"http://127.0.0.1:{port}/api/v1/tenants/{harness.tenant_id}/principals:by-email"
            f"?{name}=Anna%40Example.com",
            headers=BOOTSTRAP,
            timeout=10,
        )
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        logger.removeHandler(records)
        logger.disabled, logger.level = saved

    assert response.status_code == 200
    assert len(response.json()["items"]) == 1
    assert records.records
    for record in records.records:
        message = record.getMessage().lower()
        assert "anna" not in message
        assert "example.com" not in message
    assert any(f"{name}=[redacted]" in record.getMessage() for record in records.records)
