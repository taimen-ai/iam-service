"""Привязка репозитория к IAM: только несекретные metadata.

`.iam/binding.json` отвечает на вопрос «с каким IAM, каким tenant и каким
audience работает этот рабочий каталог». Он коммитится в репозиторий, поэтому
секрета в нём быть не может: файл проверяется на признаки credential и
отклоняется целиком, если что-то похожее найдено (ADR-0012, «не принято»).

Отсутствие binding — это отказ, а не молчаливый переход к глобальной
конфигурации: непривязанный репозиторий не должен получать credential чужого
проекта.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from iam_client.errors import BindingError

BINDING_DIRECTORY = ".iam"
BINDING_FILENAME = "binding.json"
ENV_BINDING_FILE = "IAM_BINDING_FILE"

DEFAULT_AUDIENCE = "control-plane"

# Имена полей, которые в binding не имеют права появиться ни на одном уровне.
# Сравнение идёт по нормализованному имени, поэтому `apiKey`, `api_key` и
# `API-KEY` — один и тот же ключ.
_SECRET_KEYS = frozenset(
    {
        "token",
        "tokens",
        "secret",
        "secrets",
        "password",
        "passphrase",
        "apikey",
        "apisecret",
        "accesstoken",
        "refreshtoken",
        "platformaccesstoken",
        "credential",
        "credentials",
        "clientsecret",
        "privatekey",
        "bootstraptoken",
    }
)

# Материал credential узнаётся по префиксу формата: и PAT, и переносимый ключ
# Control Plane начинаются с фиксированного тега.
_SECRET_VALUE_PREFIXES = ("iam_pat_", "cp_")


def _normalize_key(key: str) -> str:
    return "".join(character for character in key.lower() if character.isalnum())


def _assert_no_secrets(value: Any, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            location = f"{path}.{key}" if path else str(key)
            if _normalize_key(str(key)) in _SECRET_KEYS:
                raise BindingError(
                    "secret_in_binding",
                    f"поле {location} выглядит как секрет; binding хранит только "
                    "несекретные metadata",
                )
            _assert_no_secrets(item, location)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _assert_no_secrets(item, f"{path}[{index}]")
        return
    if isinstance(value, str) and value.startswith(_SECRET_VALUE_PREFIXES):
        raise BindingError(
            "secret_in_binding",
            f"значение {path or 'binding'} похоже на credential; "
            "секрет не хранится в репозитории",
        )


@dataclass(frozen=True)
class Binding:
    """Несекретная привязка рабочего каталога."""

    iam_url: str
    tenant_id: str
    audience: str
    control_plane_url: str
    scopes: tuple[str, ...]
    path: Path

    @property
    def account(self) -> str:
        """Ключ записи в credential store.

        Один и тот же Principal может работать с несколькими IAM или
        tenant'ами, поэтому секрет адресуется парой, а не одним URL.
        """

        return f"{self.iam_url}|{self.tenant_id}"

    def require_control_plane(self) -> str:
        if not self.control_plane_url:
            raise BindingError(
                "control_plane_url_required",
                f"{self.path} не содержит controlPlaneUrl: открывать Harness Session негде",
            )
        return self.control_plane_url


def find_binding_file(start: Path | None = None, *, environ: dict[str, str] | None = None) -> Path:
    """Найти binding: явный путь из окружения либо `.iam/binding.json` вверх по дереву."""

    env = os.environ if environ is None else environ
    explicit = env.get(ENV_BINDING_FILE, "").strip()
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise BindingError("repository_not_bound", f"{ENV_BINDING_FILE} указывает в никуда")
        return path
    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        candidate = directory / BINDING_DIRECTORY / BINDING_FILENAME
        if candidate.is_file():
            return candidate
    raise BindingError(
        "repository_not_bound",
        f"рабочий каталог не привязан к IAM: нет {BINDING_DIRECTORY}/{BINDING_FILENAME}",
    )


def load_binding(start: Path | None = None, *, environ: dict[str, str] | None = None) -> Binding:
    path = find_binding_file(start, environ=environ)
    try:
        document = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise BindingError("invalid_binding", f"{path} нечитаем или не является JSON") from exc
    if not isinstance(document, dict):
        raise BindingError("invalid_binding", f"{path} должен содержать объект")

    _assert_no_secrets(document)

    iam_url = str(document.get("iamUrl", "")).strip().rstrip("/")
    tenant_id = str(document.get("tenantId", "")).strip()
    if not iam_url.startswith(("http://", "https://")):
        raise BindingError("invalid_binding", f"{path}: iamUrl должен быть http(s) URL")
    if not tenant_id:
        raise BindingError("invalid_binding", f"{path}: tenantId обязателен")

    audience = str(document.get("audience", DEFAULT_AUDIENCE)).strip() or DEFAULT_AUDIENCE
    control_plane_url = str(document.get("controlPlaneUrl", "")).strip().rstrip("/")
    raw_scopes = document.get("scopes", [])
    if not isinstance(raw_scopes, list) or any(not isinstance(item, str) for item in raw_scopes):
        raise BindingError("invalid_binding", f"{path}: scopes должен быть списком строк")

    return Binding(
        iam_url=iam_url,
        tenant_id=tenant_id,
        audience=audience,
        control_plane_url=control_plane_url,
        scopes=tuple(sorted(set(raw_scopes))),
        path=path,
    )
