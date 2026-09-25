"""Схемы запросов и ответов каналов как способа входа."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Channel = Literal["telegram"]

# Идентификатор аккаунта в канале. Для Telegram это числовой user id; формат
# сверяется ещё раз по каналу в маршруте, здесь — только общая граница.
_SUBJECT = r"^[A-Za-z0-9_.:-]{1,200}$"
# Непрозрачная ссылка на предмет решения, которую адаптер получил вместе с
# уведомлением. IAM её не толкует, только переносит в token и audit.
_PURPOSE_REF = r"^[A-Za-z0-9_.:/@-]{1,200}$"


class ChannelProviderUpdate(BaseModel):
    status: Literal["active", "disabled"]

    model_config = ConfigDict(extra="forbid")


class ChannelProviderView(BaseModel):
    channel: str
    status: str
    updated_at: datetime = Field(alias="updatedAt")

    model_config = ConfigDict(populate_by_name=True)


class ChannelLinkIntentCreate(BaseModel):
    channel: Channel

    model_config = ConfigDict(extra="forbid")


class ChannelLinkIntentIssued(BaseModel):
    """Код показывается один раз: сервер хранит только его hash."""

    intent_id: uuid.UUID = Field(alias="intentId")
    channel: str
    code: str
    expires_at: datetime = Field(alias="expiresAt")

    model_config = ConfigDict(populate_by_name=True)


class ChannelLinkConfirm(BaseModel):
    channel: Channel
    code: str = Field(min_length=1, max_length=200)
    external_subject: str = Field(alias="externalSubject", pattern=_SUBJECT)

    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class ChannelLinkView(BaseModel):
    link_id: uuid.UUID = Field(alias="linkId")
    principal_id: uuid.UUID = Field(alias="principalId")
    channel: str
    status: str
    linked_at: datetime = Field(alias="linkedAt")
    last_used_at: datetime | None = Field(alias="lastUsedAt", default=None)

    model_config = ConfigDict(populate_by_name=True)


class ChannelAssertionExchange(BaseModel):
    """Адаптер канала подтверждает: этот аккаунт сейчас принял решение."""

    channel: Channel
    external_subject: str = Field(alias="externalSubject", pattern=_SUBJECT)
    purpose_ref: str = Field(alias="purposeRef", pattern=_PURPOSE_REF)

    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class ChannelAssertionToken(BaseModel):
    access_token: str = Field(alias="accessToken")
    token_type: str = Field(alias="tokenType", default="Bearer")
    expires_in: int = Field(alias="expiresIn")
    audience: str
    scope: list[str]
    session_id: uuid.UUID = Field(alias="sessionId")
    principal_id: uuid.UUID = Field(alias="principalId")
    purpose_ref: str = Field(alias="purposeRef")

    model_config = ConfigDict(populate_by_name=True)
