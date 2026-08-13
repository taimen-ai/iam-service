from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import jwt

from iam_service.federation.errors import FederationError

ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384")
REQUIRED_CLAIMS = ("iss", "sub", "aud", "exp", "iat")


@dataclass(frozen=True)
class AuthenticationContext:
    acr: str | None
    amr: tuple[str, ...]
    auth_time: datetime | None


@dataclass(frozen=True)
class UpstreamClaims:
    subject: str
    external_id: str
    groups: tuple[str, ...]
    context: AuthenticationContext


def verify_upstream_token(
    token: str,
    *,
    keys: jwt.PyJWKSet,
    issuer: str,
    audience: str,
) -> dict[str, Any]:
    """Проверяет upstream OIDC token: подпись, точный issuer, точный audience.

    Симметричные алгоритмы и `none` отклоняются до обращения к ключу, поэтому
    подставной token не может выбрать алгоритм проверки за сервер.
    """

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise FederationError("invalid_token") from exc

    algorithm = header.get("alg")
    if algorithm not in ALLOWED_ALGORITHMS:
        raise FederationError("unsupported_algorithm")
    key_id = header.get("kid")
    if not key_id:
        raise FederationError("unknown_signing_key")
    try:
        signing_key = keys[key_id]
    except (KeyError, jwt.PyJWKSetError) as exc:
        raise FederationError("unknown_signing_key") from exc

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=[algorithm],
            issuer=issuer,
            audience=audience,
            options={"require": list(REQUIRED_CLAIMS)},
        )
    except jwt.ExpiredSignatureError as exc:
        raise FederationError("token_expired") from exc
    except jwt.InvalidIssuerError as exc:
        raise FederationError("invalid_issuer") from exc
    except jwt.InvalidAudienceError as exc:
        raise FederationError("invalid_audience") from exc
    except jwt.InvalidSignatureError as exc:
        raise FederationError("invalid_signature") from exc
    except jwt.PyJWTError as exc:
        raise FederationError("invalid_token") from exc
    return dict(claims)


def read_claims(
    claims: Mapping[str, Any],
    *,
    subject_claim: str,
    external_id_claim: str,
    group_claim: str,
) -> UpstreamClaims:
    subject = _string_claim(claims, subject_claim)
    if not subject:
        raise FederationError("missing_subject_claim")
    external_id = _string_claim(claims, external_id_claim) or subject
    return UpstreamClaims(
        subject=subject,
        external_id=external_id,
        groups=_string_list(claims.get(group_claim)),
        context=AuthenticationContext(
            acr=_string_claim(claims, "acr") or None,
            amr=_string_list(claims.get("amr")),
            auth_time=_timestamp(claims.get("auth_time")),
        ),
    )


def ensure_authentication_context(
    context: AuthenticationContext,
    *,
    required_acr_values: Sequence[str],
    required_amr_values: Sequence[str],
) -> None:
    """Step-up: недостаточный authentication context закрывается, а не понижается."""

    if required_acr_values and (context.acr is None or context.acr not in required_acr_values):
        raise FederationError("step_up_required", status_code=403)
    if required_amr_values and not set(required_amr_values).issubset(context.amr):
        raise FederationError("step_up_required", status_code=403)


def project_groups(groups: Sequence[str], *, mappings: Mapping[str, str]) -> tuple[str, ...]:
    """Проекция upstream-групп в IAM group keys строго по allowlist.

    Группа без явного mapping не создаёт членство: конфигурация IdP не может
    молча расширить набор IAM-групп.
    """

    normalized = {key.strip().lstrip("/"): value for key, value in mappings.items()}
    projected = {
        normalized[group.strip().lstrip("/")]
        for group in groups
        if group.strip().lstrip("/") in normalized
    }
    return tuple(sorted(projected))


def _string_claim(claims: Mapping[str, Any], name: str) -> str:
    value = claims.get(name)
    return value if isinstance(value, str) else ""


def _string_list(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, int | float) and not isinstance(value, bool):
        return datetime.fromtimestamp(value, tz=UTC)
    return None
