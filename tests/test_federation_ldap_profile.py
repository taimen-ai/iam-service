from __future__ import annotations

from typing import Any

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


def register(client: TestClient, idp: FakeIdentityProvider, *, slug: str, **overrides: Any) -> str:
    tenant = client.post(
        "/api/v1/tenants", headers=BOOTSTRAP, json={"slug": slug, "name": slug.upper()}
    ).json()
    body: dict[str, Any] = {
        "key": "keycloak",
        "issuer": idp.issuer,
        "audience": idp.audience,
        "groupMappings": {"platform-operators": "operators"},
    }
    body.update(overrides)
    created = client.post(
        f"/api/v1/tenants/{tenant['id']}/identity-providers", headers=BOOTSTRAP, json=body
    )
    assert created.status_code == 201, created.text
    return tenant["id"]


def authenticate(client: TestClient, tenant_id: str, token: str):
    return client.post(
        f"/api/v1/tenants/{tenant_id}/federation:authenticate",
        json={"identityProvider": "keycloak", "token": token},
    )


def test_read_only_profile_keeps_identity_writes_in_the_upstream_directory(
    tmp_path, idp: FakeIdentityProvider, fetcher: FakeFetcher
) -> None:
    with build_client(tmp_path, fetcher) as client:
        read_only = register(client, idp, slug="tenant-ldap")
        managed = register(client, idp, slug="tenant-managed", lifecycleProfile="managed")
        principal = client.post(
            f"/api/v1/tenants/{read_only}/principals",
            headers=BOOTSTRAP,
            json={"kind": "human", "displayName": "Alice"},
        ).json()
        managed_principal = client.post(
            f"/api/v1/tenants/{managed}/principals",
            headers=BOOTSTRAP,
            json={"kind": "human", "displayName": "Bob"},
        ).json()
        manual_link = client.post(
            f"/api/v1/tenants/{read_only}/principals/{principal['id']}/external-identities",
            headers=BOOTSTRAP,
            json={"issuer": idp.issuer, "subject": "ldap-managed-subject"},
        )
        managed_link = client.post(
            f"/api/v1/tenants/{managed}/principals/{managed_principal['id']}/external-identities",
            headers=BOOTSTRAP,
            json={"issuer": idp.issuer, "subject": "manually-managed-subject"},
        )

    # READ_ONLY population управляется upstream-каталогом: локальная запись
    # identity закрыта, чтобы SCIM/LDAP и ручные writes не расходились.
    assert manual_link.status_code == 409
    assert manual_link.json()["detail"] == "identity_provider_managed"
    assert managed_link.status_code == 201


def test_group_projection_revokes_only_what_federation_created(
    tmp_path, idp: FakeIdentityProvider, fetcher: FakeFetcher
) -> None:
    with build_client(tmp_path, fetcher) as client:
        tenant_id = register(client, idp, slug="tenant-groups")
        with_group = authenticate(
            client, tenant_id, idp.token(claims={"groups": ["platform-operators"]})
        )
        principal_id = with_group.json()["principalId"]
        local_group = client.post(
            f"/api/v1/tenants/{tenant_id}/groups",
            headers=BOOTSTRAP,
            json={"key": "local-team", "name": "Local Team"},
        ).json()
        local_membership = client.post(
            f"/api/v1/tenants/{tenant_id}/groups/{local_group['id']}/members",
            headers=BOOTSTRAP,
            json={"principalId": principal_id},
        )
        federated_group_id = next(
            event["payload"]["groupId"]
            for event in client.get("/api/v1/events", headers=BOOTSTRAP).json()["items"]
            if event["type"] == "group.created" and event["payload"]["key"] == "operators"
        )
        local_write_to_federated_group = client.post(
            f"/api/v1/tenants/{tenant_id}/groups/{federated_group_id}/members",
            headers=BOOTSTRAP,
            json={"principalId": principal_id},
        )
        without_group = authenticate(client, tenant_id, idp.token(claims={"groups": []}))
        events = client.get("/api/v1/events", headers=BOOTSTRAP).json()["items"]

    assert with_group.json()["groups"] == ["operators"]
    assert local_membership.status_code == 201
    # Federated группа не редактируется локально: её состав задаёт upstream.
    assert local_write_to_federated_group.status_code == 409
    assert local_write_to_federated_group.json()["detail"] == "group_is_federated"

    assert without_group.status_code == 200
    assert without_group.json()["groups"] == []
    removed = [event for event in events if event["type"] == "group_membership.removed"]
    assert [event["payload"]["groupId"] for event in removed] == [federated_group_id]
    assert local_group["id"] not in [event["payload"]["groupId"] for event in removed]
