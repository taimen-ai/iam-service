from fastapi.testclient import TestClient

from iam_service.app import create_app
from iam_service.config import Settings


def test_group_membership_cannot_cross_tenant_boundary(tmp_path) -> None:
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'iam.db'}",
        bootstrap_token="test-bootstrap-token",
        create_schema_on_startup=True,
    )
    headers = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}

    with TestClient(create_app(settings)) as client:
        tenants = [
            client.post(
                "/api/v1/tenants",
                headers=headers,
                json={"slug": f"tenant-{suffix}", "name": suffix.upper()},
            ).json()
            for suffix in ("a", "b")
        ]
        principals = [
            client.post(
                f"/api/v1/tenants/{tenant['id']}/principals",
                headers=headers,
                json={"kind": "human", "displayName": name},
            ).json()
            for tenant, name in zip(tenants, ("Alice", "Bob"), strict=True)
        ]
        group = client.post(
            f"/api/v1/tenants/{tenants[0]['id']}/groups",
            headers=headers,
            json={"key": "operators", "name": "Operators"},
        ).json()
        accepted = client.post(
            f"/api/v1/tenants/{tenants[0]['id']}/groups/{group['id']}/members",
            headers=headers,
            json={"principalId": principals[0]["id"]},
        )
        rejected = client.post(
            f"/api/v1/tenants/{tenants[0]['id']}/groups/{group['id']}/members",
            headers=headers,
            json={"principalId": principals[1]["id"]},
        )

    assert accepted.status_code == 201
    assert rejected.status_code == 404
    assert rejected.json()["detail"] == "principal_not_found"
