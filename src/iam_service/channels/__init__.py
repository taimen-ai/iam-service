"""Канал (Telegram) как способ входа человека: привязка и обмен assertion.

Пакет самодостаточен, как `pat` и `scim`: свои таблицы, схемы и роутер.
Точка интеграции в `iam_service.app` — один `include_router`.
"""

from iam_service.channels.models import CHANNELS, ChannelLinkIntent, ChannelProvider
from iam_service.channels.routes import channel_issuer, create_channel_router

__all__ = [
    "CHANNELS",
    "ChannelLinkIntent",
    "ChannelProvider",
    "channel_issuer",
    "create_channel_router",
]
