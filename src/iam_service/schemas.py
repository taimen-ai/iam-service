import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class TenantCreate(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,78}[a-z0-9]$")
    name: str = Field(min_length=1, max_length=200)
    # Единый tenant платформы (суперпроект ADR-0030): id можно задать явно, чтобы
    # IAM, Control Plane и platform-core именовали один tenant одним UUID.
    id: uuid.UUID | None = None


class TenantView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    slug: str
    name: str
    status: str
    created_at: datetime


class PrincipalCreate(BaseModel):
    kind: str = Field(pattern=r"^(human|agent|service_account|workload)$")
    display_name: str = Field(alias="displayName", min_length=1, max_length=200)


class PrincipalView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: str
    display_name: str
    status: str
    created_at: datetime


class ExternalIdentityCreate(BaseModel):
    issuer: str = Field(min_length=1, max_length=500)
    subject: str = Field(min_length=1, max_length=500)


class ExternalIdentityView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    principal_id: uuid.UUID
    issuer: str
    subject: str
    status: str
    created_at: datetime


class IdentityProviderCreate(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,118}[a-z0-9]$")
    issuer: str = Field(min_length=1, max_length=500)
    audience: str = Field(min_length=1, max_length=200)
    jwks_uri: str = Field(alias="jwksUri", default="", max_length=500)
    subject_claim: str = Field(alias="subjectClaim", default="sub", max_length=80)
    external_id_claim: str = Field(alias="externalIdClaim", default="sub", max_length=80)
    group_claim: str = Field(alias="groupClaim", default="groups", max_length=80)
    group_mappings: dict[str, str] = Field(alias="groupMappings", default_factory=dict)
    required_acr_values: list[str] = Field(alias="requiredAcrValues", default_factory=list)
    required_amr_values: list[str] = Field(alias="requiredAmrValues", default_factory=list)
    lifecycle_profile: str = Field(
        alias="lifecycleProfile", default="read_only", pattern=r"^(read_only|managed)$"
    )
    jwks_cache_ttl_seconds: int = Field(alias="jwksCacheTtlSeconds", default=300, ge=0, le=86400)
    jwks_stale_grace_seconds: int = Field(
        alias="jwksStaleGraceSeconds", default=900, ge=0, le=86400
    )

    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class IdentityProviderView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    key: str
    issuer: str
    audience: str
    jwks_uri: str
    subject_claim: str
    external_id_claim: str
    group_claim: str
    group_mappings: dict[str, str]
    required_acr_values: list[str]
    required_amr_values: list[str]
    lifecycle_profile: str
    status: str


class FederationAuthenticateRequest(BaseModel):
    """Federation принимает только upstream token.

    `extra="forbid"` не даёт клиенту прислать LDAP username/password: пароль
    проверяет исключительно IdP, IAM его никогда не видит.
    """

    identity_provider: str = Field(alias="identityProvider", min_length=1, max_length=120)
    token: str = Field(min_length=1)

    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class FederationAuthenticationContext(BaseModel):
    acr: str | None = None
    amr: list[str] = Field(default_factory=list)
    auth_time: datetime | None = Field(alias="authTime", default=None)

    model_config = ConfigDict(populate_by_name=True)


class FederatedIdentityView(BaseModel):
    principal_id: uuid.UUID = Field(alias="principalId")
    identity_provider: str = Field(alias="identityProvider")
    groups: list[str]
    authentication_context: FederationAuthenticationContext = Field(alias="authenticationContext")
    identity_provider_stale: bool = Field(alias="identityProviderStale", default=False)

    model_config = ConfigDict(populate_by_name=True)


class FederationExchangeRequest(BaseModel):
    """Вход через upstream IdP плюс выпуск credential одного audience.

    Нужен шлюзу, который действует от имени человека в браузере: у того есть
    только upstream token, а не Platform Access Token. Тот же `extra="forbid"`,
    что у `federation:authenticate`: пароль каталога сюда не попадает.
    """

    identity_provider: str = Field(alias="identityProvider", min_length=1, max_length=120)
    token: str = Field(min_length=1)
    audience: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class FederationExchangeResponse(BaseModel):
    access_token: str = Field(alias="accessToken")
    token_type: str = Field(alias="tokenType", default="Bearer")
    expires_in: int = Field(alias="expiresIn")
    audience: str
    scope: list[str]
    session_id: uuid.UUID = Field(alias="sessionId")
    principal_id: uuid.UUID = Field(alias="principalId")
    identity_provider: str = Field(alias="identityProvider")
    groups: list[str]
    authentication_context: FederationAuthenticationContext = Field(alias="authenticationContext")
    identity_provider_stale: bool = Field(alias="identityProviderStale", default=False)

    model_config = ConfigDict(populate_by_name=True)


class AudienceCreate(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,118}[a-z0-9]$")
    allowed_scopes: list[str] = Field(alias="allowedScopes", default_factory=list)


class AudienceUpdate(BaseModel):
    """Замена списка allowed scopes audience (bootstrap): новый scope появляется у
    сервиса раньше, чем у уже заведённого audience."""

    allowed_scopes: list[str] = Field(alias="allowedScopes")


class AudienceView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    key: str
    allowed_scopes: list[str]
    status: str


class ServiceAccountCreate(BaseModel):
    display_name: str = Field(alias="displayName", min_length=1, max_length=200)
    audiences: list[str] = Field(min_length=1)
    scope_ceiling: list[str] = Field(alias="scopeCeiling", default_factory=list)


class ServiceAccountIssued(BaseModel):
    principal_id: uuid.UUID = Field(alias="principalId")
    client_id: str = Field(alias="clientId")
    client_secret: str = Field(alias="clientSecret")

    model_config = ConfigDict(populate_by_name=True)


class GroupCreate(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,118}[a-z0-9]$")
    name: str = Field(min_length=1, max_length=200)


class GroupView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    key: str
    name: str
    status: str


class GroupMemberCreate(BaseModel):
    principal_id: uuid.UUID = Field(alias="principalId")


class GroupMemberView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    group_id: uuid.UUID
    principal_id: uuid.UUID


class TokenExchangeRequest(BaseModel):
    client_id: str = Field(alias="clientId")
    client_secret: str = Field(alias="clientSecret")
    audience: str
    scopes: list[str] = Field(default_factory=list)


class TokenResponse(BaseModel):
    access_token: str = Field(alias="accessToken")
    token_type: str = Field(alias="tokenType", default="Bearer")
    expires_in: int = Field(alias="expiresIn")

    model_config = ConfigDict(populate_by_name=True)


class EventView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sequence: int
    id: uuid.UUID
    tenant_id: uuid.UUID
    type: str
    aggregate_type: str
    aggregate_id: uuid.UUID
    payload: dict[str, object]
    occurred_at: datetime


class EventPage(BaseModel):
    items: list[EventView]
    next_after: int | None
