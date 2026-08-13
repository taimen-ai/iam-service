"""Интеграционная проверка против reference deployment из `deploy/keycloak`.

Тест пропускается, пока не заданы переменные окружения стенда, поэтому обычный
`pytest` остаётся автономным. Пароль каталога используется только здесь и только
против самого Keycloak: iam-service его не видит и не принимает.
"""

from __future__ import annotations

import os

import httpx
import pytest
from fastapi.testclient import TestClient

from iam_service.app import create_app
from iam_service.config import Settings

BOOTSTRAP = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}

ISSUER = os.environ.get("IAM_TEST_OIDC_ISSUER", "")
AUDIENCE = os.environ.get("IAM_TEST_OIDC_AUDIENCE", "iam-service")
CLIENT_ID = os.environ.get("IAM_TEST_OIDC_CLIENT_ID", "local-verification")
DIRECTORY_USER = os.environ.get("IAM_TEST_DIRECTORY_USER", "directory-operator")
DIRECTORY_PASSWORD = os.environ.get("IAM_TEST_DIRECTORY_PASSWORD", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not (ISSUER and DIRECTORY_PASSWORD),
        reason="set IAM_TEST_OIDC_ISSUER and IAM_TEST_DIRECTORY_PASSWORD to run against the stand",
    ),
]


def upstream_access_token() -> str:
    response = httpx.post(
        f"{ISSUER}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "username": DIRECTORY_USER,
            "password": DIRECTORY_PASSWORD,
        },
        timeout=10.0,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def test_ldap_user_from_keycloak_becomes_a_principal_with_projected_groups(tmp_path) -> None:
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'iam.db'}",
        bootstrap_token="test-bootstrap-token",
        create_schema_on_startup=True,
    )
    token = upstream_access_token()

    with TestClient(create_app(settings)) as client:
        tenant = client.post(
            "/api/v1/tenants", headers=BOOTSTRAP, json={"slug": "tenant-a", "name": "A"}
        ).json()
        provider = client.post(
            f"/api/v1/tenants/{tenant['id']}/identity-providers",
            headers=BOOTSTRAP,
            json={
                "key": "keycloak",
                "issuer": ISSUER,
                "audience": AUDIENCE,
                "externalIdClaim": "ldap_id",
                "groupMappings": {"platform-operators": "operators"},
                "lifecycleProfile": "read_only",
            },
        )
        authenticated = client.post(
            f"/api/v1/tenants/{tenant['id']}/federation:authenticate",
            json={"identityProvider": "keycloak", "token": token},
        )
        replayed = client.post(
            f"/api/v1/tenants/{tenant['id']}/federation:authenticate",
            json={"identityProvider": "keycloak", "token": token},
        )
        wrong_audience = client.post(
            f"/api/v1/tenants/{tenant['id']}/identity-providers",
            headers=BOOTSTRAP,
            json={"key": "keycloak-other-audience", "issuer": ISSUER, "audience": "other-service"},
        )
        events = client.get("/api/v1/events", headers=BOOTSTRAP).text

    assert provider.status_code == 201, provider.text
    assert authenticated.status_code == 200, authenticated.text
    assert authenticated.json()["groups"] == ["operators"]
    assert authenticated.json()["authenticationContext"]["acr"]
    assert replayed.json()["principalId"] == authenticated.json()["principalId"]
    assert wrong_audience.status_code == 409  # один issuer регистрируется один раз
    assert DIRECTORY_PASSWORD not in events
    assert token not in events
