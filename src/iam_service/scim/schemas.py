"""Представления SCIM 2.0 (RFC 7643) и сообщения протокола (RFC 7644).

Поддерживается только тот набор атрибутов, который IAM действительно хранит:
идентификаторы population и состояние lifecycle. `name`, `emails`, `phoneNumbers`
и прочие профильные атрибуты принимаются и отбрасываются — IAM не является
каталогом персональных данных, и `/scim/v2/Schemas` объявляет это явно.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SERVICE_PROVIDER_CONFIG_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"


class ScimUserRequest(BaseModel):
    """Тело `POST`/`PUT` для `Users`.

    `externalId` обязателен: сопоставление ведётся по стабильному внешнему
    идентификатору, а `userName` может меняться вместе с почтой сотрудника.
    """

    schemas: list[str] = Field(default_factory=lambda: [USER_SCHEMA])
    external_id: str = Field(alias="externalId", min_length=1, max_length=500)
    user_name: str = Field(alias="userName", min_length=1, max_length=320)
    display_name: str = Field(alias="displayName", default="", max_length=200)
    active: bool = True

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class ScimMemberRequest(BaseModel):
    value: str = Field(min_length=1, max_length=200)

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class ScimGroupRequest(BaseModel):
    schemas: list[str] = Field(default_factory=lambda: [GROUP_SCHEMA])
    external_id: str | None = Field(alias="externalId", default=None, max_length=500)
    display_name: str = Field(alias="displayName", min_length=1, max_length=200)
    members: list[ScimMemberRequest] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class ScimPatchOperation(BaseModel):
    op: str = Field(min_length=1, max_length=20)
    path: str | None = None
    value: Any = None

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class ScimPatchRequest(BaseModel):
    schemas: list[str] = Field(default_factory=lambda: [PATCH_OP_SCHEMA])
    operations: list[ScimPatchOperation] = Field(alias="Operations", min_length=1)

    model_config = ConfigDict(populate_by_name=True, extra="ignore")


def _meta(
    resource_type: str, *, resource_id: str, created: datetime, modified: datetime, version: int
) -> dict[str, Any]:
    return {
        "resourceType": resource_type,
        "created": created.isoformat(),
        "lastModified": modified.isoformat(),
        "location": f"/scim/v2/{resource_type}s/{resource_id}",
        "version": etag(version),
    }


def etag(version: int) -> str:
    return f'W/"{version}"'


def user_representation(user: Any, *, groups: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "schemas": [USER_SCHEMA],
        "id": str(user.id),
        "externalId": user.external_id,
        "userName": user.user_name,
        "displayName": user.display_name,
        "active": bool(user.active),
        "groups": groups,
        "meta": _meta(
            "User",
            resource_id=str(user.id),
            created=user.created_at,
            modified=user.updated_at,
            version=user.version,
        ),
    }


def group_representation(group: Any, *, members: list[dict[str, str]]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schemas": [GROUP_SCHEMA],
        "id": str(group.id),
        "displayName": group.display_name,
        "members": members,
        "meta": _meta(
            "Group",
            resource_id=str(group.id),
            created=group.created_at,
            modified=group.updated_at,
            version=group.version,
        ),
    }
    if group.external_id is not None:
        payload["externalId"] = group.external_id
    return payload


def list_response(
    resources: list[dict[str, Any]], *, total: int, start_index: int
) -> dict[str, Any]:
    return {
        "schemas": [LIST_RESPONSE_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


def service_provider_config() -> dict[str, Any]:
    """Объявление возможностей провайдера (RFC 7643 §5).

    Bulk и sort не поддерживаются осознанно: reconciliation построена на
    постраничном чтении и точечных PATCH, а не на пакетных операциях.
    """

    return {
        "schemas": [SERVICE_PROVIDER_CONFIG_SCHEMA],
        "documentationUri": "https://www.rfc-editor.org/rfc/rfc7644",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": True},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": (
                    "Audience-bound access token confidential service identity; "
                    "человеческий credential не принимается"
                ),
                "primary": True,
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": "/scim/v2/ServiceProviderConfig",
        },
    }


def resource_types() -> dict[str, Any]:
    types = [
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": USER_SCHEMA,
            "meta": {"resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/User"},
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "schema": GROUP_SCHEMA,
            "meta": {"resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/Group"},
        },
    ]
    return list_response(types, total=len(types), start_index=1)


def _attribute(name: str, *, required: bool = False, unique: str = "none") -> dict[str, Any]:
    return {
        "name": name,
        "type": "string",
        "multiValued": False,
        "required": required,
        "caseExact": False,
        "mutability": "readWrite",
        "returned": "default",
        "uniqueness": unique,
    }


def schemas_document() -> dict[str, Any]:
    """Поддерживаемые атрибуты.

    Список намеренно короткий: клиент должен видеть, что профильные и
    контактные атрибуты не сохраняются, а не узнавать это опытным путём.
    """

    documents = [
        {
            "id": USER_SCHEMA,
            "name": "User",
            "description": "Provisioned identity projected onto an IAM Principal",
            "attributes": [
                _attribute("externalId", required=True, unique="server"),
                _attribute("userName", required=True, unique="server"),
                _attribute("displayName"),
                {**_attribute("active"), "type": "boolean"},
            ],
            "meta": {"resourceType": "Schema", "location": f"/scim/v2/Schemas/{USER_SCHEMA}"},
        },
        {
            "id": GROUP_SCHEMA,
            "name": "Group",
            "description": "Provisioned group projected onto a global IAM Group",
            "attributes": [
                _attribute("externalId", unique="server"),
                _attribute("displayName", required=True, unique="server"),
                {**_attribute("members"), "multiValued": True, "type": "complex"},
            ],
            "meta": {"resourceType": "Schema", "location": f"/scim/v2/Schemas/{GROUP_SCHEMA}"},
        },
    ]
    return list_response(documents, total=len(documents), start_index=1)
