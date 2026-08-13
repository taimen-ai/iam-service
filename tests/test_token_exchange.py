import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from iam_service.app import create_app
from iam_service.config import Settings
from iam_service.tokens import verify_access_token


def test_service_credential_is_bound_to_one_audience_and_secret_is_not_in_events(tmp_path) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'iam.db'}",
        bootstrap_token="test-bootstrap-token",
        issuer="https://iam.example",
        signing_private_key=private_pem,
        create_schema_on_startup=True,
    )
    headers = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}

    with TestClient(create_app(settings)) as client:
        tenant = client.post(
            "/api/v1/tenants", headers=headers, json={"slug": "tenant-a", "name": "A"}
        ).json()
        for audience in ("control-plane", "memory-service"):
            response = client.post(
                f"/api/v1/tenants/{tenant['id']}/audiences",
                headers=headers,
                json={"key": audience, "allowedScopes": ["read", "write"]},
            )
            assert response.status_code == 201
        account = client.post(
            f"/api/v1/tenants/{tenant['id']}/service-accounts",
            headers=headers,
            json={
                "displayName": "Control Plane adapter",
                "audiences": ["control-plane"],
                "scopeCeiling": ["read"],
            },
        ).json()
        exchanged = client.post(
            "/api/v1/tokens/exchange",
            json={
                "clientId": account["clientId"],
                "clientSecret": account["clientSecret"],
                "audience": "control-plane",
                "scopes": ["read"],
            },
        )
        wrong_audience = client.post(
            "/api/v1/tokens/exchange",
            json={
                "clientId": account["clientId"],
                "clientSecret": account["clientSecret"],
                "audience": "memory-service",
                "scopes": ["read"],
            },
        )
        unknown_scope = client.post(
            "/api/v1/tokens/exchange",
            json={
                "clientId": account["clientId"],
                "clientSecret": account["clientSecret"],
                "audience": "control-plane",
                "scopes": ["admin"],
            },
        )
        events = client.get("/api/v1/events", headers=headers).text

    assert exchanged.status_code == 200
    assert wrong_audience.status_code == 403
    assert wrong_audience.json()["detail"] == "audience_not_allowed"
    assert unknown_scope.status_code == 403
    assert unknown_scope.json()["detail"] == "scope_not_allowed"
    claims = verify_access_token(
        exchanged.json()["accessToken"],
        public_key=public_pem,
        issuer="https://iam.example",
        audience="control-plane",
    )
    assert claims["tenant_id"] == tenant["id"]
    assert claims["scope"] == ["read"]
    with pytest.raises(jwt.InvalidAudienceError):
        verify_access_token(
            exchanged.json()["accessToken"],
            public_key=public_pem,
            issuer="https://iam.example",
            audience="memory-service",
        )
    assert account["clientSecret"] not in events
