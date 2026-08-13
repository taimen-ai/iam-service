"""Криптографический материал Platform Access Token.

Формат ADR-0012: ``iam_pat_<public-prefix>_<secret>``. Сервер хранит только
lookup prefix и SHA-256 полного токена; полный секрет показывается ровно один
раз при выпуске и не восстановим из БД.

SHA-256 без KDF выбран сознательно: секрет — 256 бит из `secrets`, словарной
атаки на него не существует, а быстрый hash не даёт DoS-поверхности на
неаутентифицированном exchange endpoint. Ровно та же функция используется
Control Plane (``cp_<prefix>_<secret>``), поэтому compatibility mapping
переносит пару ``(key_prefix, key_hash)`` без передачи открытого ключа.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

PAT_TAG = "iam_pat"
LEGACY_TAG = "cp"

KIND_PLATFORM_ACCESS_TOKEN = "platform_access_token"
KIND_LEGACY_CONTROL_PLANE_API_KEY = "legacy_control_plane_api_key"

# 12 hex-символов = 48 бит: столкновение по unique index нереально, а prefix
# остаётся коротким и пригодным для audit и UI.
PREFIX_LENGTH = 12
_SECRET_BYTES = 32
_HASH_LENGTH = 64


@dataclass(frozen=True)
class GeneratedCredential:
    """Результат выпуска: полный токен существует только в этом объекте."""

    full_token: str
    public_prefix: str
    secret_hash: str


@dataclass(frozen=True)
class PresentedCredential:
    """Разобранный предъявленный токен без секретной части."""

    kind: str
    public_prefix: str


def hash_credential(full_token: str) -> str:
    return hashlib.sha256(full_token.encode()).hexdigest()


def generate_platform_access_token() -> GeneratedCredential:
    prefix = secrets.token_hex(PREFIX_LENGTH // 2)
    secret = secrets.token_urlsafe(_SECRET_BYTES)
    full_token = f"{PAT_TAG}_{prefix}_{secret}"
    return GeneratedCredential(
        full_token=full_token,
        public_prefix=prefix,
        secret_hash=hash_credential(full_token),
    )


def is_valid_prefix(prefix: str) -> bool:
    if len(prefix) != PREFIX_LENGTH:
        return False
    return all(character in "0123456789abcdef" for character in prefix)


def is_valid_hash(value: str) -> bool:
    if len(value) != _HASH_LENGTH:
        return False
    return all(character in "0123456789abcdef" for character in value)


def parse_presented_credential(full_token: str) -> PresentedCredential | None:
    """Определить вид и lookup prefix предъявленного токена.

    Возвращает None для любого нераспознанного материала — включая
    audience-specific access token, который на этом endpoint не принимается.
    """

    if full_token.startswith(f"{PAT_TAG}_"):
        parts = full_token.split("_", 3)
        if len(parts) != 4 or not parts[3] or not is_valid_prefix(parts[2]):
            return None
        return PresentedCredential(kind=KIND_PLATFORM_ACCESS_TOKEN, public_prefix=parts[2])
    if full_token.startswith(f"{LEGACY_TAG}_"):
        parts = full_token.split("_", 2)
        if len(parts) != 3 or not parts[2] or not is_valid_prefix(parts[1]):
            return None
        return PresentedCredential(kind=KIND_LEGACY_CONTROL_PLANE_API_KEY, public_prefix=parts[1])
    return None


def matches_stored_hash(full_token: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_credential(full_token), stored_hash)
