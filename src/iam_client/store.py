"""Локальное хранилище Platform Access Token.

Порядок разрешения по ADR-0012: явно объявленный CI/runtime environment, затем
OS credential store, затем защищённый файл `0600` как fallback. Репозиторий,
MCP-манифест и tracked-настройки источником секрета не являются никогда.

Environment-переменная читается только тогда, когда режим объявлен явно
(`IAM_CREDENTIAL_MODE=environment`). Случайно унаследованная переменная не
должна незаметно подменять credential разработчика, поэтому её наличие без
объявленного режима — ошибка, а не тихий выбор источника.
"""

from __future__ import annotations

import json
import os
import platform
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from iam_client.errors import CredentialError

ENV_MODE = "IAM_CREDENTIAL_MODE"
ENV_TOKEN = "IAM_PLATFORM_ACCESS_TOKEN"
ENV_NO_KEYCHAIN = "IAM_NO_KEYCHAIN"
ENV_CONFIG_HOME = "XDG_CONFIG_HOME"

KEYCHAIN_SERVICE = "iam.platform-access-token"
_ENVIRONMENT_MODES = frozenset({"environment", "ci"})

SOURCE_ENVIRONMENT = "environment"
SOURCE_KEYCHAIN = "keychain"
SOURCE_FILE = "file"


@dataclass(frozen=True)
class ResolvedCredential:
    """Найденный секрет и место, откуда он взят.

    `location` пригоден для вывода человеку и в диагностику: он описывает
    хранилище, но не содержит ни секрета, ни его части.
    """

    token: str
    source: str
    location: str


class Keychain(Protocol):
    """OS credential store; подменяется в тестах."""

    def available(self) -> bool: ...

    def get(self, account: str) -> str | None: ...

    def set(self, account: str, token: str) -> bool: ...

    def delete(self, account: str) -> None: ...


class NullKeychain:
    """Заглушка для платформ без поддерживаемого OS credential store."""

    def available(self) -> bool:
        return False

    def get(self, account: str) -> str | None:
        return None

    def set(self, account: str, token: str) -> bool:
        return False

    def delete(self, account: str) -> None:
        return None


class MacKeychain:
    """macOS Keychain через `security`.

    Секрет передаётся исключительно через stdin: `security -w <secret>`
    показал бы его в таблице процессов любому пользователю машины.
    """

    def __init__(self, environ: Mapping[str, str]) -> None:
        self._environ = environ

    def available(self) -> bool:
        if platform.system() != "Darwin":
            return False
        return self._environ.get(ENV_NO_KEYCHAIN) != "1"

    def get(self, account: str) -> str | None:
        try:
            result = subprocess.run(
                ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        token = result.stdout.strip()
        return token if result.returncode == 0 and token else None

    def set(self, account: str, token: str) -> bool:
        try:
            result = subprocess.run(
                [
                    "security",
                    "add-generic-password",
                    "-U",
                    "-s",
                    KEYCHAIN_SERVICE,
                    "-a",
                    account,
                    "-w",
                ],
                input=f"{token}\n{token}\n".encode(),
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if result.returncode != 0:
            return False
        # Интерактивный prompt мог не принять ввод: убеждаемся, что значение легло.
        return self.get(account) == token

    def delete(self, account: str) -> None:
        subprocess.run(
            ["security", "delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account],
            capture_output=True,
            timeout=5,
            check=False,
        )


class CredentialStore:
    """Разрешение, сохранение и удаление секрета для пары IAM + tenant."""

    def __init__(
        self,
        *,
        environ: Mapping[str, str] | None = None,
        keychain: Keychain | None = None,
        home: Path | None = None,
    ) -> None:
        self._environ = os.environ if environ is None else environ
        self._keychain = keychain if keychain is not None else MacKeychain(self._environ)
        self._home = home

    # -- расположение файла ---------------------------------------------------

    def credentials_path(self) -> Path:
        configured = self._environ.get(ENV_CONFIG_HOME, "").strip()
        if configured:
            base = Path(configured)
        elif self._home is not None:
            base = self._home / ".config"
        else:
            base = Path.home() / ".config"
        return base / "iam" / "credentials.json"

    # -- источники ------------------------------------------------------------

    def environment_mode(self) -> bool:
        return self._environ.get(ENV_MODE, "").strip().lower() in _ENVIRONMENT_MODES

    def _environment_token(self) -> str | None:
        token = self._environ.get(ENV_TOKEN, "").strip()
        if not token:
            return None
        if not self.environment_mode():
            raise CredentialError(
                "environment_mode_required",
                f"{ENV_TOKEN} задан, но режим не объявлен: установите "
                f"{ENV_MODE}=environment для управляемого CI/runtime окружения",
            )
        return token

    def _file_document(self) -> dict[str, dict[str, str]]:
        path = self.credentials_path()
        if not path.exists():
            return {}
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            # Файл, доступный кому-то ещё, не читаем: расширенные права —
            # это уже инцидент, а не мелкая неточность конфигурации.
            raise CredentialError(
                "credentials_file_permissions",
                f"{path} имеет права {mode:o}; ожидается 600",
            )
        try:
            document = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            raise CredentialError("credentials_file_unreadable", f"{path} нечитаем") from exc
        return document if isinstance(document, dict) else {}

    def _write_file_document(self, document: dict[str, dict[str, str]]) -> Path:
        path = self.credentials_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        body = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
        # Файл создаётся сразу с 0600: запись с последующим chmod оставила бы
        # окно, в котором секрет читается по умолчанию umask.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(descriptor, body.encode())
        finally:
            os.close(descriptor)
        path.chmod(0o600)
        return path

    # -- операции -------------------------------------------------------------

    def resolve(self, account: str) -> ResolvedCredential | None:
        token = self._environment_token()
        if token:
            return ResolvedCredential(token=token, source=SOURCE_ENVIRONMENT, location=ENV_TOKEN)
        if self._keychain.available():
            token = self._keychain.get(account)
            if token:
                return ResolvedCredential(
                    token=token, source=SOURCE_KEYCHAIN, location=KEYCHAIN_SERVICE
                )
        entry = self._file_document().get(account)
        if entry and entry.get("token"):
            return ResolvedCredential(
                token=str(entry["token"]),
                source=SOURCE_FILE,
                location=str(self.credentials_path()),
            )
        return None

    def store(self, account: str, token: str) -> ResolvedCredential:
        if self.environment_mode():
            raise CredentialError(
                "environment_mode_read_only",
                f"в режиме {ENV_MODE}=environment credential задаётся окружением, "
                "а не локальным входом",
            )
        if self._keychain.available() and self._keychain.set(account, token):
            return ResolvedCredential(
                token=token, source=SOURCE_KEYCHAIN, location=KEYCHAIN_SERVICE
            )
        document = self._file_document()
        document[account] = {"token": token}
        path = self._write_file_document(document)
        return ResolvedCredential(token=token, source=SOURCE_FILE, location=str(path))

    def delete(self, account: str) -> bool:
        removed = False
        if self._keychain.available():
            if self._keychain.get(account):
                removed = True
            self._keychain.delete(account)
        document = self._file_document()
        if account in document:
            del document[account]
            self._write_file_document(document)
            removed = True
        return removed
