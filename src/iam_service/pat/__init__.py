"""Platform Access Token: principal-bound credential и обмен на audience token.

Пакет намеренно самодостаточен: он добавляет свои таблицы, схемы и роутер,
не переписывая federation- и service-account-код. Точка интеграции в
`iam_service.app` — один `include_router`.
"""

from iam_service.pat.material import (
    LEGACY_TAG,
    PAT_TAG,
    PresentedCredential,
    generate_platform_access_token,
    hash_credential,
    parse_presented_credential,
)
from iam_service.pat.models import AuthenticationContext, PlatformAccessToken
from iam_service.pat.routes import (
    create_platform_token_router,
    credential_payload,
    record_authentication_context,
    revoke_credential,
    revoke_tokens_for_principal,
)

__all__ = [
    "LEGACY_TAG",
    "PAT_TAG",
    "AuthenticationContext",
    "PlatformAccessToken",
    "PresentedCredential",
    "create_platform_token_router",
    "credential_payload",
    "generate_platform_access_token",
    "hash_credential",
    "parse_presented_credential",
    "record_authentication_context",
    "revoke_credential",
    "revoke_tokens_for_principal",
]
