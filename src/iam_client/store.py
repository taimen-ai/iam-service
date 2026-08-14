"""Локальное хранилище Platform Access Token.

Порядок разрешения по ADR-0012: явно объявленный CI/runtime environment, затем
OS credential store, затем защищённый файл `0600` как fallback. Репозиторий,
MCP-манифест и tracked-настройки источником секрета не являются никогда.

Environment-переменная читается только тогда, когда режим объявлен явно
(`IAM_CREDENTIAL_MODE=environment`). Случайно унаследованная переменная не
должна незаметно подменять credential разработчика, поэтому её наличие без
объявленного режима — ошибка, а не тихий выбор источника.

Запись адресуется тройкой `issuer|tenant|principal`. Пары `issuer|tenant` не
хватает: на одной машине под одним пользователем работают несколько
исполнителей одного тенанта, и по паре их записи совпадают — второй секрет
затирал бы первый. Различить их путями (`XDG_CONFIG_HOME`) можно, но ошибка
тогда проявляется молча: агент ходит под чужой identity, и видно это только в
audit. Старые двухчастные записи читаются по-прежнему, пока они на машине
единственные; как только исполнителей становится несколько, выбор наугад
заменяется отказом.
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
from typing import Any, Protocol

from iam_client.errors import CredentialError

ENV_MODE = "IAM_CREDENTIAL_MODE"
ENV_TOKEN = "IAM_PLATFORM_ACCESS_TOKEN"
ENV_NO_KEYCHAIN = "IAM_NO_KEYCHAIN"
ENV_CONFIG_HOME = "XDG_CONFIG_HOME"
# «Кто я на этой машине»: нужен там, где рядом работают несколько исполнителей
# одного тенанта. Один исполнитель по-прежнему обходится без него.
ENV_PRINCIPAL = "IAM_PRINCIPAL"
# Секция файла со списком принадлежностей: имена без секретов, нужна чтобы
# знать об исполнителях, чей секрет лежит в OS credential store.
INDEX_KEY = "principals"

KEYCHAIN_SERVICE = "iam.platform-access-token"
_ENVIRONMENT_MODES = frozenset({"environment", "ci"})

SOURCE_ENVIRONMENT = "environment"
SOURCE_KEYCHAIN = "keychain"
SOURCE_FILE = "file"


@dataclass(frozen=True)
class ResolvedCredential:
    """Найденный секрет и место, откуда он взят.

    `location` пригоден для вывода человеку и в диагностику: он описывает
    хранилище, но не содержит ни секрета, ни его части. `principal_id` пуст,
    когда секрет пришёл из окружения или из записи старого формата: там
    принадлежность не записана.
    """

    token: str
    source: str
    location: str
    principal_id: str = ""


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

    def _file_document(self) -> dict[str, Any]:
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

    def _write_file_document(self, document: dict[str, Any]) -> Path:
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

    # -- адресация записей ----------------------------------------------------

    def entry_key(self, account: str, principal_id: str) -> str:
        """Ключ записи: тройка, когда Principal известен, иначе старая пара."""
        return f"{account}|{principal_id}" if principal_id else account

    def principals(self, account: str) -> list[str]:
        """Кто из Principal этой пары живёт на машине, по мнению файла.

        Секрет может лежать в OS credential store, который не перечисляется, —
        поэтому файл ведёт отдельную секцию с одними принадлежностями, без
        секретов. Без неё процесс, не назвавший себя, не смог бы даже узнать,
        что выбор неоднозначен.
        """
        document = self._file_document()
        found = list(self._index(document).get(account, []))
        for key, entry in document.items():
            if key in (account, INDEX_KEY) or not key.startswith(f"{account}|"):
                continue
            if isinstance(entry, dict) and entry.get("token"):
                found.append(str(entry.get("principalId", "")) or key[len(account) + 1 :])
        return list(dict.fromkeys(found))

    def _index(self, document: Mapping[str, Any]) -> dict[str, list[str]]:
        section = document.get(INDEX_KEY)
        if not isinstance(section, dict):
            return {}
        return {
            str(account): [str(item) for item in listed if item]
            for account, listed in section.items()
            if isinstance(listed, list)
        }

    def _legacy_entry(self, account: str, principal_id: str) -> tuple[str, str] | None:
        """Запись старого формата, если она наша.

        Чужая запись под старым ключом — не запасной вариант, а именно та
        подмена identity, которую здесь чинят.
        """
        entry = self._file_document().get(account)
        if not isinstance(entry, dict) or not entry.get("token"):
            return None
        owner = str(entry.get("principalId", ""))
        if principal_id and owner and owner != principal_id:
            return None
        return str(entry["token"]), owner or principal_id

    # -- операции -------------------------------------------------------------

    def resolve(self, account: str, *, principal_id: str = "") -> ResolvedCredential | None:
        token = self._environment_token()
        if token:
            return ResolvedCredential(token=token, source=SOURCE_ENVIRONMENT, location=ENV_TOKEN)

        wanted = principal_id
        if not wanted:
            known = [owner for owner in self.principals(account) if owner]
            if len(known) > 1:
                # Выбрать одного из нескольких — это и есть тихая подмена
                # identity: процесс продолжит работать, но не от своего имени,
                # и заметно это станет только в audit.
                raise CredentialError(
                    "credential_ambiguous",
                    f"на этой машине несколько credential для {account}: "
                    f"укажите {ENV_PRINCIPAL}=<principal-id>, чей использовать",
                )
            wanted = known[0] if known else ""

        if self._keychain.available():
            for key in dict.fromkeys([self.entry_key(account, wanted), account]):
                token = self._keychain.get(key)
                if token:
                    return ResolvedCredential(
                        token=token,
                        source=SOURCE_KEYCHAIN,
                        location=KEYCHAIN_SERVICE,
                        principal_id=wanted,
                    )

        document = self._file_document()
        entry = document.get(self.entry_key(account, wanted)) if wanted else None
        if isinstance(entry, dict) and entry.get("token"):
            return ResolvedCredential(
                token=str(entry["token"]),
                source=SOURCE_FILE,
                location=str(self.credentials_path()),
                principal_id=str(entry.get("principalId", "")) or wanted,
            )
        legacy = self._legacy_entry(account, principal_id)
        if legacy is not None:
            return ResolvedCredential(
                token=legacy[0],
                source=SOURCE_FILE,
                location=str(self.credentials_path()),
                principal_id=legacy[1],
            )
        return None

    def store(self, account: str, token: str, *, principal_id: str) -> ResolvedCredential:
        if self.environment_mode():
            raise CredentialError(
                "environment_mode_read_only",
                f"в режиме {ENV_MODE}=environment credential задаётся окружением, "
                "а не локальным входом",
            )
        if not principal_id:
            # Без принадлежности запись снова становится неразличимой, а это и
            # есть починенная ошибка. Principal известен из introspect, поэтому
            # его отсутствие — дефект вызывающего кода, а не выбор режима.
            raise CredentialError(
                "principal_required", "credential сохраняется только вместе с его Principal"
            )
        key = self.entry_key(account, principal_id)
        if self._keychain.available() and self._keychain.set(key, token):
            # Секрет остался в OS credential store; на диск уходит только имя
            # владельца, иначе процесс, не назвавший себя, не узнает даже того,
            # что выбор неоднозначен.
            self._remember_principal(account, principal_id)
            return ResolvedCredential(
                token=token,
                source=SOURCE_KEYCHAIN,
                location=KEYCHAIN_SERVICE,
                principal_id=principal_id,
            )
        document = self._file_document()
        document[key] = {"token": token, "principalId": principal_id}
        legacy = document.get(account)
        if isinstance(legacy, dict) and legacy.get("token") == token:
            # Та же самая запись в старом формате: это вход того же Principal,
            # переносим её, а не оставляем вторым кандидатом. Чужую запись
            # старого формата не трогаем — потерять её было бы не лучше, чем
            # подменить.
            del document[account]
        path = self._write_file_document(document)
        return ResolvedCredential(
            token=token, source=SOURCE_FILE, location=str(path), principal_id=principal_id
        )

    def _remember_principal(self, account: str, principal_id: str) -> None:
        """Записать принадлежность без секрета: индекс исполнителей машины."""
        document = self._file_document()
        index = self._index(document)
        listed = index.get(account, [])
        if principal_id in listed:
            return
        index[account] = [*listed, principal_id]
        document[INDEX_KEY] = index
        self._write_file_document(document)

    def _forget_principal(self, document: dict[str, Any], account: str, principal_id: str) -> bool:
        index = self._index(document)
        listed = index.get(account, [])
        if principal_id not in listed:
            return False
        remaining = [item for item in listed if item != principal_id]
        if remaining:
            index[account] = remaining
        else:
            index.pop(account, None)
        if index:
            document[INDEX_KEY] = index
        else:
            document.pop(INDEX_KEY, None)
        return True

    def delete(self, account: str, *, principal_id: str = "") -> bool:
        removed = False
        keys = list(dict.fromkeys([self.entry_key(account, principal_id), account]))
        if self._keychain.available():
            for key in keys:
                if self._keychain.get(key):
                    removed = True
                self._keychain.delete(key)
        document = self._file_document()
        dropped = False
        for key in keys:
            entry = document.get(key)
            if not isinstance(entry, dict) or not entry.get("token"):
                continue
            owner = str(entry.get("principalId", ""))
            if key == account and principal_id and owner and owner != principal_id:
                continue  # чужая запись старого формата
            del document[key]
            dropped = True
        if principal_id and self._forget_principal(document, account, principal_id):
            dropped = True
        if dropped:
            # Пишем файл только когда из него действительно что-то ушло: иначе
            # выход из keychain-хранилища создавал бы пустой файл на диске.
            self._write_file_document(document)
        return removed or dropped
