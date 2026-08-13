"""Открытие Harness Session в Control Plane после обмена токена.

Codex и Claude Code — разные harness одного человека: они предъявляют один
Platform Access Token, но каждый открывает собственную session со своим
`harness_type`. `control_level` объявляет не клиент: Control Plane выводит
`human_operated` из вида Principal, подтверждённого IAM-токеном.
"""

from __future__ import annotations

import platform
from collections.abc import Iterable
from dataclasses import dataclass

import httpx

from iam_client.client import DEFAULT_TIMEOUT
from iam_client.errors import RemoteError

# Версия harness-протокола, объявляемая при открытии session.
PROTOCOL_VERSION = "2"

# Поддерживаемые локальные harness. Значение уходит в Control Plane как есть,
# поэтому session Codex и session Claude Code различимы в audit и списках.
SUPPORTED_HARNESS_TYPES = ("codex", "claude-code")


@dataclass(frozen=True)
class HarnessSession:
    """Открытая session Control Plane; секрет в неё не входит."""

    id: str
    principal_id: str
    control_level: str
    harness_type: str
    client_name: str
    expires_at: str


def open_harness_session(
    control_plane_url: str,
    access_token: str,
    *,
    harness_type: str,
    client_name: str,
    client_version: str = "",
    capabilities: Iterable[str] = (),
    include_hostname: bool = True,
    transport: httpx.BaseTransport | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> HarnessSession:
    """Открыть session, предъявив audience-bound access token.

    В `environment` не кладётся ничего о локальной машине сверх hostname:
    абсолютные пути рабочего каталога не являются operational state и не
    должны попадать в Control Plane.
    """

    body: dict[str, object] = {
        "clientName": client_name,
        "clientVersion": client_version,
        "harness": {
            "type": harness_type,
            "version": client_version,
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": sorted(set(capabilities)),
            "hostname": platform.node() if include_hostname else None,
            "environment": {},
        },
    }
    url = f"{control_plane_url.rstrip('/')}/api/v1/sessions"
    try:
        with httpx.Client(transport=transport, timeout=timeout) as client:
            response = client.post(
                url, json=body, headers={"Authorization": f"Bearer {access_token}"}
            )
    except httpx.HTTPError as exc:
        raise RemoteError(
            "control_plane_unreachable", f"Control Plane недоступен: {type(exc).__name__}"
        ) from exc
    if response.status_code >= 400:
        raise RemoteError(
            "control_plane_error",
            f"Control Plane ответил {response.status_code} на открытие session",
            status_code=response.status_code,
        )
    session = response.json()
    return HarnessSession(
        id=str(session["id"]),
        principal_id=str(session["principalId"]),
        control_level=str(session["controlLevel"]),
        harness_type=str(session.get("harnessType") or harness_type),
        client_name=str(session.get("clientName") or client_name),
        expires_at=str(session.get("expiresAt", "")),
    )
