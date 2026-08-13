from fastapi.testclient import TestClient

from iam_service.app import create_app
from iam_service.config import Settings


def test_external_identity_is_unique_and_principal_is_tenant_scoped(tmp_path) -> None:
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'iam.db'}",
        bootstrap_token="test-bootstrap-token",
        create_schema_on_startup=True,
    )
    headers = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}

    with TestClient(create_app(settings)) as client:
        tenant_a = client.post(
            "/api/v1/tenants", headers=headers, json={"slug": "tenant-a", "name": "A"}
        ).json()
        tenant_b = client.post(
            "/api/v1/tenants", headers=headers, json={"slug": "tenant-b", "name": "B"}
        ).json()
        principal_a = client.post(
            f"/api/v1/tenants/{tenant_a['id']}/principals",
            headers=headers,
            json={"kind": "human", "displayName": "Alice"},
        ).json()
        principal_b = client.post(
            f"/api/v1/tenants/{tenant_b['id']}/principals",
            headers=headers,
            json={"kind": "human", "displayName": "Bob"},
        ).json()
        linked = client.post(
            f"/api/v1/tenants/{tenant_a['id']}/principals/{principal_a['id']}/external-identities",
            headers=headers,
            json={"issuer": "https://id.example", "subject": "stable-subject"},
        )
        duplicate = client.post(
            f"/api/v1/tenants/{tenant_b['id']}/principals/{principal_b['id']}/external-identities",
            headers=headers,
            json={"issuer": "https://id.example", "subject": "stable-subject"},
        )
        cross_tenant = client.get(
            f"/api/v1/tenants/{tenant_b['id']}/principals/{principal_a['id']}",
            headers=headers,
        )

    assert linked.status_code == 201
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"] == "external_identity_exists"
    assert cross_tenant.status_code == 404
