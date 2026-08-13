from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from iam_service.app import create_app
from iam_service.config import Settings


def test_revoked_service_account_cannot_exchange_another_token(tmp_path) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'iam.db'}",
        bootstrap_token="test-bootstrap-token",
        signing_private_key=private_pem,
        create_schema_on_startup=True,
    )
    headers = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}

    with TestClient(create_app(settings)) as client:
        tenant = client.post(
            "/api/v1/tenants", headers=headers, json={"slug": "tenant-a", "name": "A"}
        ).json()
        client.post(
            f"/api/v1/tenants/{tenant['id']}/audiences",
            headers=headers,
            json={"key": "control-plane", "allowedScopes": ["read"]},
        )
        account = client.post(
            f"/api/v1/tenants/{tenant['id']}/service-accounts",
            headers=headers,
            json={
                "displayName": "Adapter",
                "audiences": ["control-plane"],
                "scopeCeiling": ["read"],
            },
        ).json()
        revoked = client.post(
            f"/api/v1/tenants/{tenant['id']}/service-accounts/{account['clientId']}:revoke",
            headers=headers,
        )
        exchanged = client.post(
            "/api/v1/tokens/exchange",
            json={
                "clientId": account["clientId"],
                "clientSecret": account["clientSecret"],
                "audience": "control-plane",
                "scopes": ["read"],
            },
        )

    assert revoked.status_code == 204
    assert exchanged.status_code == 401
    assert exchanged.json()["detail"] == "invalid_client"
