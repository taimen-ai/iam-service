"""HTTP-контракты агентов владельца.

Владелец не объявляет ни tenant, ни себя: оба берутся из его подписанного
token. `extra="forbid"` не даёт прислать `ownerPrincipalId` или `kind`.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AgentCreate(BaseModel):
    display_name: str = Field(alias="displayName", min_length=1, max_length=200)

    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class AgentView(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID
    kind: str
    display_name: str = Field(serialization_alias="displayName")
    status: str
    owner_principal_id: uuid.UUID = Field(serialization_alias="ownerPrincipalId")
    created_at: datetime = Field(serialization_alias="createdAt")


class AgentPlatformAccessTokenCreate(BaseModel):
    """Выпуск PAT агента его владельцем.

    Срок обязателен: credential агента выпускает контроллер, а не человек, и
    бессрочного умолчания у такого пути быть не должно.
    """

    name: str = Field(min_length=1, max_length=200)
    audiences: list[str] = Field(min_length=1)
    scope_ceiling: list[str] = Field(alias="scopeCeiling", default_factory=list)
    expires_in_seconds: int = Field(alias="expiresInSeconds", ge=60)

    model_config = ConfigDict(populate_by_name=True, extra="forbid")
