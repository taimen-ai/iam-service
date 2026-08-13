"""HTTP-контракты Platform Access Token.

`extra="forbid"` везде, где клиент мог бы прислать лишнее: это блокирует
попытку передать открытый секрет в import legacy-креденшла и попытку клиента
самому объявить tenant, principal или entitlement.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AuthenticationContextRecord(BaseModel):
    """Регистрация подтверждённого human authentication.

    Пароли, коды MFA и upstream-токены сюда не передаются: запись фиксирует
    только факт и параметры входа.
    """

    issuer: str = Field(min_length=1, max_length=500)
    acr: str | None = Field(default=None, max_length=200)
    amr: list[str] = Field(default_factory=list)
    auth_time: datetime | None = Field(alias="authTime", default=None)
    external_identity_id: uuid.UUID | None = Field(alias="externalIdentityId", default=None)

    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class AuthenticationContextView(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    principal_id: uuid.UUID = Field(serialization_alias="principalId")
    issuer: str
    acr: str | None = None
    amr: list[str]
    auth_time: datetime = Field(serialization_alias="authTime")
    recorded_at: datetime = Field(serialization_alias="recordedAt")
    source: str


class PlatformAccessTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    audiences: list[str] = Field(min_length=1)
    scope_ceiling: list[str] = Field(alias="scopeCeiling", default_factory=list)
    expires_in_seconds: int | None = Field(alias="expiresInSeconds", default=None, ge=60)

    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class PlatformAccessTokenRotate(BaseModel):
    """Ротация не принимает ни scope, ни audience, ни срок.

    Новый токен наследует authority и `expires_at` предшественника: ротация
    меняет секрет, но не может расширить полномочия или продлить окно.
    """

    model_config = ConfigDict(extra="forbid")


class LegacyCredentialImport(BaseModel):
    """Перенос существующего Control Plane API key на период миграции.

    Принимается только пара `(keyPrefix, keyHash)` — открытый ключ остаётся в
    руках владельца и не пересекает границу сервисов.
    """

    principal_id: uuid.UUID = Field(alias="principalId")
    name: str = Field(min_length=1, max_length=200)
    key_prefix: str = Field(alias="keyPrefix", min_length=12, max_length=12)
    key_hash: str = Field(alias="keyHash", min_length=64, max_length=64)
    audience: str = Field(min_length=1, max_length=120)
    scope_ceiling: list[str] = Field(alias="scopeCeiling", default_factory=list)
    expires_in_seconds: int = Field(alias="expiresInSeconds", ge=60)

    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class PlatformAccessTokenView(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    tenant_id: uuid.UUID = Field(serialization_alias="tenantId")
    principal_id: uuid.UUID = Field(serialization_alias="principalId")
    name: str
    kind: str
    public_prefix: str = Field(serialization_alias="publicPrefix")
    audiences: list[str]
    scope_ceiling: list[str] = Field(serialization_alias="scopeCeiling")
    created_at: datetime = Field(serialization_alias="createdAt")
    expires_at: datetime = Field(serialization_alias="expiresAt")
    last_used_at: datetime | None = Field(serialization_alias="lastUsedAt", default=None)
    revoked_at: datetime | None = Field(serialization_alias="revokedAt", default=None)
    revoke_reason: str = Field(serialization_alias="revokeReason", default="")
    rotated_from_id: uuid.UUID | None = Field(serialization_alias="rotatedFromId", default=None)


class PlatformAccessTokenIssued(BaseModel):
    """Ответ выпуска. `token` заполняется ровно один раз.

    При idempotent повторе (ambiguous response) поле равно `null`: секрет не
    хранится server-side и не может быть показан повторно.
    """

    model_config = ConfigDict(populate_by_name=True)

    credential: PlatformAccessTokenView
    token: str | None = None


class PlatformTokenExchangeRequest(BaseModel):
    """Обмен PAT на короткоживущий credential одного audience.

    Tenant и Principal выводятся из самого токена, а не из тела запроса.
    """

    token: str = Field(min_length=1)
    audience: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class PlatformTokenIntrospectRequest(BaseModel):
    """Проверка предъявленного PAT без выпуска нового credential.

    Нужна `iam auth status`: локальный плагин узнаёт, кем он вошёл и до
    какого момента годится токен, не запрашивая доступ ни к одному audience.
    """

    token: str = Field(min_length=1)

    model_config = ConfigDict(extra="forbid")


class PlatformTokenIntrospection(BaseModel):
    """Несекретный снимок записи токена.

    Секрет и его hash не возвращаются ни в каком виде: наружу выходят только
    identity, границы authority и срок.
    """

    model_config = ConfigDict(populate_by_name=True)

    tenant_id: uuid.UUID = Field(serialization_alias="tenantId")
    principal_id: uuid.UUID = Field(serialization_alias="principalId")
    principal_kind: str = Field(serialization_alias="principalKind")
    display_name: str = Field(serialization_alias="displayName")
    credential_id: uuid.UUID = Field(serialization_alias="credentialId")
    name: str
    public_prefix: str = Field(serialization_alias="publicPrefix")
    audiences: list[str]
    scope_ceiling: list[str] = Field(serialization_alias="scopeCeiling")
    expires_at: datetime = Field(serialization_alias="expiresAt")
    issued_at: datetime = Field(serialization_alias="issuedAt")


class PlatformTokenSelfRevokeRequest(BaseModel):
    """Отзыв предъявленного токена его же владельцем (`iam auth logout`)."""

    token: str = Field(min_length=1)
    reason: str = Field(default="logout", max_length=200)

    model_config = ConfigDict(extra="forbid")


class PlatformTokenExchangeResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    access_token: str = Field(serialization_alias="accessToken")
    token_type: str = Field(serialization_alias="tokenType", default="Bearer")
    expires_in: int = Field(serialization_alias="expiresIn")
    audience: str
    scope: list[str]
    session_id: uuid.UUID = Field(serialization_alias="sessionId")


class PrincipalDisabled(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    principal_id: uuid.UUID = Field(serialization_alias="principalId")
    status: str
    revoked_credentials: int = Field(serialization_alias="revokedCredentials")
