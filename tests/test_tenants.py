from fastapi.testclient import TestClient

from iam_service.app import create_app
from iam_service.config import Settings


def test_bootstrap_tenant_is_visible_in_event_journal(tmp_path) -> None:
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'iam.db'}",
        bootstrap_token="test-bootstrap-token",
        create_schema_on_startup=True,
    )

    with TestClient(create_app(settings)) as client:
        created = client.post(
            "/api/v1/tenants",
            headers={"X-IAM-Bootstrap-Token": "test-bootstrap-token"},
            json={"slug": "acme", "name": "Acme"},
        )
        events = client.get(
            "/api/v1/events",
            headers={"X-IAM-Bootstrap-Token": "test-bootstrap-token"},
        )

    assert created.status_code == 201
    assert created.json()["slug"] == "acme"
    assert events.status_code == 200
    assert [item["type"] for item in events.json()["items"]] == ["tenant.created"]


def test_tenant_can_be_created_with_an_explicit_id(tmp_path) -> None:
    """Единый tenant платформы: id задаёт bootstrap суперпроекта, повтор — 409."""
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'iam.db'}",
        bootstrap_token="test-bootstrap-token",
        create_schema_on_startup=True,
    )
    headers = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}
    wanted = "3f2b9a6e-1c4d-4e8f-9a0b-5c6d7e8f9a0b"
    with TestClient(create_app(settings)) as client:
        created = client.post(
            "/api/v1/tenants", headers=headers, json={"slug": "acme", "name": "Acme", "id": wanted}
        )
        assert created.status_code == 201
        assert created.json()["id"] == wanted
        again = client.post(
            "/api/v1/tenants", headers=headers, json={"slug": "other", "name": "O", "id": wanted}
        )
        assert again.status_code == 409
        assert again.json()["detail"] == "tenant_id_exists"
