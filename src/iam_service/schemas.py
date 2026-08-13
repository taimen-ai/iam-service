import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class TenantCreate(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,78}[a-z0-9]$")
    name: str = Field(min_length=1, max_length=200)


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


class AudienceCreate(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,118}[a-z0-9]$")
    allowed_scopes: list[str] = Field(alias="allowedScopes", default_factory=list)


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
