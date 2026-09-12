"""Реестр audiences: список и замена allowed scopes (bootstrap-операции)."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from iam_service.app import create_app
from iam_service.config import Settings

BOOTSTRAP = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}


def _private_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _client(tmp_path) -> TestClient:
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'iam.db'}",
        bootstrap_token="test-bootstrap-token",
        create_schema_on_startup=True,
        signing_private_key=_private_pem(),
    )
    return TestClient(create_app(settings))


def test_list_and_update_allowed_scopes(tmp_path) -> None:
    with _client(tmp_path) as client:
        tenant = client.post(
            "/api/v1/tenants", headers=BOOTSTRAP, json={"slug": "acme", "name": "ACME"}
        ).json()
        base = f"/api/v1/tenants/{tenant['id']}/audiences"
        client.post(
            base,
            headers=BOOTSTRAP,
            json={"key": "memory-service", "allowedScopes": ["memory:read"]},
        )
        client.post(base, headers=BOOTSTRAP, json={"key": "control-plane", "allowedScopes": []})

        listed = client.get(base, headers=BOOTSTRAP)
        assert listed.status_code == 200
        assert [a["key"] for a in listed.json()] == ["control-plane", "memory-service"]

        updated = client.patch(
            f"{base}/memory-service",
            headers=BOOTSTRAP,
            json={"allowedScopes": ["memory:write", "memory:read", "memory:tenants"]},
        )
        assert updated.status_code == 200
        assert updated.json()["allowed_scopes"] == ["memory:read", "memory:tenants", "memory:write"]
        # Идемпотентно: повтор с тем же набором — тот же ответ.
        again = client.patch(
            f"{base}/memory-service",
            headers=BOOTSTRAP,
            json={"allowedScopes": ["memory:tenants", "memory:read", "memory:write"]},
        )
        assert again.status_code == 200
        assert again.json()["allowed_scopes"] == updated.json()["allowed_scopes"]

        # Расширенный потолок сразу действует при обмене service account.
        account = client.post(
            f"/api/v1/tenants/{tenant['id']}/service-accounts",
            headers=BOOTSTRAP,
            json={
                "displayName": "Control Plane",
                "audiences": ["memory-service"],
                "scopeCeiling": ["memory:read", "memory:tenants"],
            },
        ).json()
        exchanged = client.post(
            "/api/v1/tokens/exchange",
            json={
                "clientId": account["clientId"],
                "clientSecret": account["clientSecret"],
                "audience": "memory-service",
                "scopes": ["memory:read", "memory:tenants"],
            },
        )
        assert exchanged.status_code == 200, exchanged.text


def test_update_unknown_audience_and_bad_scope(tmp_path) -> None:
    with _client(tmp_path) as client:
        tenant = client.post(
            "/api/v1/tenants", headers=BOOTSTRAP, json={"slug": "acme", "name": "ACME"}
        ).json()
        base = f"/api/v1/tenants/{tenant['id']}/audiences"
        missing = client.patch(f"{base}/nope", headers=BOOTSTRAP, json={"allowedScopes": ["x"]})
        assert missing.status_code == 404
        client.post(base, headers=BOOTSTRAP, json={"key": "bidops", "allowedScopes": []})
        bad = client.patch(f"{base}/bidops", headers=BOOTSTRAP, json={"allowedScopes": [""]})
        assert bad.status_code == 422
        # Без bootstrap-токена реестр недоступен.
        assert client.get(base).status_code == 401
