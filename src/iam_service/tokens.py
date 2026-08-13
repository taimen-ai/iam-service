from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class TokenIssuer:
    def __init__(self, *, issuer: str, private_key: str, key_id: str, ttl_seconds: int) -> None:
        if not private_key:
            raise ValueError("IAM_SIGNING_PRIVATE_KEY is required for token exchange")
        loaded = serialization.load_pem_private_key(private_key.encode(), password=None)
        if not isinstance(loaded, RSAPrivateKey):
            raise ValueError("IAM signing key must be an RSA private key")
        self.private_key = loaded
        self.issuer = issuer
        self.key_id = key_id
        self.ttl_seconds = ttl_seconds

    def issue(
        self,
        *,
        subject: uuid.UUID,
        tenant_id: uuid.UUID,
        audience: str,
        scopes: list[str],
        credential_id: uuid.UUID,
    ) -> str:
        now = datetime.now(UTC)
        return jwt.encode(
            {
                "iss": self.issuer,
                "sub": str(subject),
                "tenant_id": str(tenant_id),
                "aud": audience,
                "scope": scopes,
                "principal_type": "service_account",
                "credential_id": str(credential_id),
                "iat": now,
                "nbf": now,
                "exp": now + timedelta(seconds=self.ttl_seconds),
                "jti": str(uuid.uuid4()),
            },
            self.private_key,
            algorithm="RS256",
            headers={"kid": self.key_id, "typ": "at+jwt"},
        )

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        public_key = self.private_key.public_key()
        numbers = public_key.public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self.key_id,
                    "n": _b64url_uint(numbers.n),
                    "e": _b64url_uint(numbers.e),
                }
            ]
        }


def verify_access_token(
    token: str, *, public_key: str | RSAPublicKey, issuer: str, audience: str
) -> dict[str, Any]:
    claims = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        issuer=issuer,
        audience=audience,
        options={"require": ["iss", "sub", "tenant_id", "aud", "iat", "nbf", "exp", "jti"]},
    )
    return dict(claims)
