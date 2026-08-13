from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import FakeFetcher, FakeIdentityProvider
from iam_service.app import create_app
from iam_service.config import Settings

BOOTSTRAP = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}


def build_client(tmp_path, fetcher: FakeFetcher) -> TestClient:
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'iam.db'}",
        bootstrap_token="test-bootstrap-token",
        create_schema_on_startup=True,
    )
    return TestClient(create_app(settings, jwks_fetcher=fetcher))


def register(
    client: TestClient,
    idp: FakeIdentityProvider,
    *,
    slug: str,
    stale_grace_seconds: int,
) -> str:
    tenant = client.post(
        "/api/v1/tenants", headers=BOOTSTRAP, json={"slug": slug, "name": slug.upper()}
    ).json()
    created = client.post(
        f"/api/v1/tenants/{tenant['id']}/identity-providers",
        headers=BOOTSTRAP,
        json={
            "key": "keycloak",
            "issuer": idp.issuer,
            "audience": idp.audience,
            "jwksCacheTtlSeconds": 0,
            "jwksStaleGraceSeconds": stale_grace_seconds,
        },
    )
    assert created.status_code == 201, created.text
    return tenant["id"]


def authenticate(client: TestClient, tenant_id: str, token: str):
    return client.post(
        f"/api/v1/tenants/{tenant_id}/federation:authenticate",
        json={"identityProvider": "keycloak", "token": token},
    )


def test_unreachable_idp_serves_bounded_stale_keys_and_then_fails_closed(
    tmp_path, idp: FakeIdentityProvider, fetcher: FakeFetcher
) -> None:
    with build_client(tmp_path, fetcher) as client:
        with_grace = register(client, idp, slug="tenant-grace", stale_grace_seconds=900)
        without_grace = register(client, idp, slug="tenant-strict", stale_grace_seconds=0)
        # Разные upstream subjects: identity одного Tenant не переносится в другой.
        grace_token = idp.token(subject="operator-in-grace-tenant")
        strict_token = idp.token(subject="operator-in-strict-tenant")
        warm_up_grace = authenticate(client, with_grace, grace_token)
        warm_up_strict = authenticate(client, without_grace, strict_token)

        fetcher.available = False
        degraded = authenticate(client, with_grace, grace_token)
        fail_closed = authenticate(client, without_grace, strict_token)

    assert warm_up_grace.status_code == 200
    assert warm_up_grace.json()["identityProviderStale"] is False
    assert warm_up_strict.status_code == 200

    # В пределах grace window вход продолжает работать, но помечен как stale.
    assert degraded.status_code == 200
    assert degraded.json()["identityProviderStale"] is True
    assert degraded.json()["principalId"] == warm_up_grace.json()["principalId"]

    # За пределами grace window ключам больше не доверяют: deny, а не allow.
    assert fail_closed.status_code == 503
    assert fail_closed.json()["detail"] == "identity_provider_unavailable"


def test_unreachable_idp_without_cached_keys_denies_login(
    tmp_path, idp: FakeIdentityProvider, fetcher: FakeFetcher
) -> None:
    with build_client(tmp_path, fetcher) as client:
        tenant_id = register(client, idp, slug="tenant-cold", stale_grace_seconds=900)
        fetcher.available = False
        response = authenticate(client, tenant_id, idp.token())
        events = client.get("/api/v1/events", headers=BOOTSTRAP).json()["items"]

    assert response.status_code == 503
    assert response.json()["detail"] == "identity_provider_unavailable"
    assert "principal.created" not in [event["type"] for event in events]
