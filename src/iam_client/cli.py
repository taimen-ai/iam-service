"""CLI `iam auth`: одинаковый вход для Codex, Claude Code и другого harness.

Секрет никогда не проходит через argv: он читается скрытым prompt или из
stdin. Попытка передать токен аргументом отклоняется до разбора команды —
аргумент виден в истории оболочки и в таблице процессов, и одного его
появления достаточно, чтобы credential считался скомпрометированным.

Вывод команд рассчитан на человека и на диагностику одновременно, поэтому в
нём нет ни секрета, ни его части: только публичный prefix токена.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

import httpx

from iam_client.binding import Binding, load_binding
from iam_client.client import IamClient, Introspection
from iam_client.errors import BindingError, CredentialError, IamClientError, RemoteError
from iam_client.harness import SUPPORTED_HARNESS_TYPES, open_harness_session
from iam_client.store import ENV_PRINCIPAL, CredentialStore, ResolvedCredential

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_UNAUTHENTICATED = 3
EXIT_REMOTE = 4

# Материал credential узнаётся по тегу формата; проверка идёт по всей строке
# аргумента, чтобы поймать и `--token=iam_pat_...`.
_CREDENTIAL_MARKERS = ("iam_pat_", "cp_")


def redact(token: str) -> str:
    """Публичное представление токена: тег и prefix, без секретной части."""

    parts = token.split("_")
    if len(parts) >= 4 and token.startswith("iam_pat_"):
        return f"iam_pat_{parts[2]}_…"
    return "…"


@dataclass
class Runtime:
    """Внешние зависимости CLI; в тестах подменяются целиком."""

    environ: Mapping[str, str]
    cwd: Path
    stdin: TextIO
    stdout: TextIO
    stderr: TextIO
    store: CredentialStore
    iam_transport: httpx.BaseTransport | None = None
    control_plane_transport: httpx.BaseTransport | None = None
    prompt: Callable[[str], str] | None = None


def _emit(runtime: Runtime, line: str = "") -> None:
    print(line, file=runtime.stdout)


def _fail(runtime: Runtime, code: str, message: str) -> None:
    print(f"iam: {code}: {message}", file=runtime.stderr)


def _client(runtime: Runtime, binding: Binding) -> IamClient:
    return IamClient(binding.iam_url, transport=runtime.iam_transport)


def _read_token(runtime: Runtime, *, from_stdin: bool) -> str:
    """Прочитать секрет скрытым prompt или из stdin."""

    if from_stdin or not runtime.stdin.isatty():
        return runtime.stdin.readline().strip()
    prompt = runtime.prompt or (lambda text: getpass.getpass(text, stream=runtime.stderr))
    return prompt("Platform Access Token: ").strip()


def _principal(runtime: Runtime) -> str:
    """Кого из исполнителей этой машины обслуживает команда.

    Пусто — «единственного»: пока на машине один credential пары, ничего
    указывать не нужно. Как только их несколько, store откажется выбирать
    вместо человека.
    """
    return runtime.environ.get(ENV_PRINCIPAL, "").strip()


def _resolved(runtime: Runtime, binding: Binding) -> ResolvedCredential | None:
    return runtime.store.resolve(binding.account, principal_id=_principal(runtime))


def _status_document(
    binding: Binding,
    credential: ResolvedCredential | None,
    introspection: Introspection | None,
    state: str,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "state": state,
        "binding": str(binding.path),
        "iamUrl": binding.iam_url,
        "tenantId": binding.tenant_id,
        "audience": binding.audience,
        "credentialSource": credential.source if credential else None,
        "credentialLocation": credential.location if credential else None,
        "tokenPrefix": redact(credential.token) if credential else None,
    }
    if introspection is not None:
        document.update(
            {
                "principalId": introspection.principal_id,
                "principalKind": introspection.principal_kind,
                "displayName": introspection.display_name,
                "credentialName": introspection.name,
                "audiences": list(introspection.audiences),
                "scopeCeiling": list(introspection.scope_ceiling),
                "expiresAt": introspection.expires_at.isoformat(),
            }
        )
    return document


def _command_login(runtime: Runtime, args: argparse.Namespace) -> int:
    binding = load_binding(runtime.cwd, environ=dict(runtime.environ))
    token = _read_token(runtime, from_stdin=args.stdin)
    if not token:
        _fail(runtime, "token_required", "Platform Access Token не введён")
        return EXIT_USAGE

    introspection = _client(runtime, binding).introspect(token)
    if introspection.tenant_id != binding.tenant_id:
        _fail(
            runtime,
            "tenant_mismatch",
            f"токен принадлежит другому tenant, чем {binding.path}",
        )
        return EXIT_UNAUTHENTICATED
    if binding.audience not in introspection.audiences:
        _fail(
            runtime,
            "audience_not_allowed",
            f"токен не выдан для audience {binding.audience}",
        )
        return EXIT_UNAUTHENTICATED

    declared = _principal(runtime)
    if declared and declared != introspection.principal_id:
        # Машина объявила, чей это процесс, а токен принадлежит другому: молча
        # записать его — значит развести identity и объявление, а разойтись они
        # могут надолго и заметно только в audit.
        _fail(
            runtime,
            "principal_mismatch",
            f"{ENV_PRINCIPAL} указывает на {declared}, "
            f"а токен принадлежит {introspection.principal_id}",
        )
        return EXIT_UNAUTHENTICATED

    stored = runtime.store.store(binding.account, token, principal_id=introspection.principal_id)
    others = [
        owner for owner in runtime.store.principals(binding.account) if owner != stored.principal_id
    ]
    _emit(runtime, f"Вход выполнен: {introspection.display_name} ({introspection.principal_id})")
    _emit(runtime, f"Токен:      {redact(token)} ({introspection.name})")
    _emit(runtime, f"Хранилище:  {stored.source} → {stored.location}")
    if others:
        # Не предупреждение о проблеме, а факт: рядом живут чужие credential,
        # поэтому процессам на этой машине нужно называть себя.
        _emit(
            runtime,
            f"Рядом хранятся credential других Principal ({len(others)}): "
            f"процессам укажите {ENV_PRINCIPAL}",
        )
    _emit(runtime, f"Действует до: {introspection.expires_at.isoformat()}")
    return EXIT_OK


def _command_status(runtime: Runtime, args: argparse.Namespace) -> int:
    binding = load_binding(runtime.cwd, environ=dict(runtime.environ))
    credential = _resolved(runtime, binding)
    if credential is None:
        if args.json:
            _emit(runtime, json.dumps(_status_document(binding, None, None, "logged_out")))
        else:
            _emit(runtime, f"Привязка:   {binding.path}")
            _emit(runtime, "Состояние:  вход не выполнен")
        return EXIT_UNAUTHENTICATED

    try:
        introspection = _client(runtime, binding).introspect(credential.token)
    except RemoteError as exc:
        if exc.code != "invalid_token":
            raise
        if args.json:
            _emit(runtime, json.dumps(_status_document(binding, credential, None, "invalid")))
        else:
            _emit(runtime, f"Привязка:   {binding.path}")
            _emit(runtime, f"Токен:      {redact(credential.token)}")
            _emit(runtime, "Состояние:  недействителен — нужен повторный вход")
        return EXIT_UNAUTHENTICATED

    if args.json:
        _emit(runtime, json.dumps(_status_document(binding, credential, introspection, "active")))
        return EXIT_OK
    _emit(runtime, f"Привязка:   {binding.path}")
    _emit(runtime, f"IAM:        {binding.iam_url} (tenant {binding.tenant_id})")
    _emit(runtime, f"Principal:  {introspection.display_name} ({introspection.principal_id})")
    _emit(runtime, f"Токен:      {redact(credential.token)} ({introspection.name})")
    _emit(runtime, f"Хранилище:  {credential.source} → {credential.location}")
    _emit(runtime, f"Audiences:  {', '.join(introspection.audiences)}")
    _emit(runtime, f"Scope ceiling: {', '.join(introspection.scope_ceiling) or '—'}")
    _emit(runtime, f"Действует до: {introspection.expires_at.isoformat()}")
    return EXIT_OK


def _command_logout(runtime: Runtime, args: argparse.Namespace) -> int:
    binding = load_binding(runtime.cwd, environ=dict(runtime.environ))
    credential = _resolved(runtime, binding)
    revoked = False
    if credential is not None and args.revoke:
        try:
            _client(runtime, binding).revoke_self(credential.token)
            revoked = True
        except RemoteError as exc:
            if exc.code != "invalid_token":
                raise
            # Сервер уже не признаёт токен: локальную копию всё равно убираем.

    removed = runtime.store.delete(
        binding.account,
        principal_id=_principal(runtime) or (credential.principal_id if credential else ""),
    )
    if credential is not None and credential.source == "environment":
        _emit(runtime, "Credential задан окружением: удалить его локально нельзя")
    _emit(runtime, "Локальный credential удалён" if removed else "Локального credential не было")
    if args.revoke:
        _emit(
            runtime,
            "Токен отозван в IAM" if revoked else "Токен в IAM уже недействителен",
        )
    else:
        _emit(runtime, "Токен в IAM остался действующим: для отзыва нужен --revoke")
    return EXIT_OK


def _command_session(runtime: Runtime, args: argparse.Namespace) -> int:
    binding = load_binding(runtime.cwd, environ=dict(runtime.environ))
    control_plane_url = binding.require_control_plane()
    credential = _resolved(runtime, binding)
    if credential is None:
        _fail(runtime, "not_authenticated", "вход не выполнен: сначала `iam auth login`")
        return EXIT_UNAUTHENTICATED

    exchanged = _client(runtime, binding).exchange(
        credential.token, audience=binding.audience, scopes=binding.scopes
    )
    session = open_harness_session(
        control_plane_url,
        exchanged.access_token,
        harness_type=args.harness,
        client_name=args.client_name or args.harness,
        client_version=args.client_version,
        transport=runtime.control_plane_transport,
    )
    document = {
        "sessionId": session.id,
        "principalId": session.principal_id,
        "controlLevel": session.control_level,
        "harnessType": session.harness_type,
        "clientName": session.client_name,
        "audience": exchanged.audience,
        "scope": list(exchanged.scope),
        "expiresAt": session.expires_at,
    }
    if args.json:
        _emit(runtime, json.dumps(document))
        return EXIT_OK
    _emit(runtime, f"Session:    {session.id}")
    _emit(runtime, f"Principal:  {session.principal_id}")
    _emit(runtime, f"Harness:    {session.harness_type} ({session.control_level})")
    _emit(runtime, f"Audience:   {exchanged.audience} [{', '.join(exchanged.scope) or '—'}]")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iam", description="Вход в IAM для локального harness")
    commands = parser.add_subparsers(dest="group", required=True)
    auth = commands.add_parser("auth", help="аутентификация локального плагина")
    subcommands = auth.add_subparsers(dest="command", required=True)

    login = subcommands.add_parser("login", help="сохранить Platform Access Token")
    login.add_argument(
        "--stdin",
        action="store_true",
        help="прочитать токен из stdin вместо скрытого prompt",
    )
    login.set_defaults(handler=_command_login)

    status = subcommands.add_parser("status", help="показать текущий вход")
    status.add_argument("--json", action="store_true", help="машиночитаемый вывод")
    status.set_defaults(handler=_command_status)

    logout = subcommands.add_parser("logout", help="удалить локальный credential")
    logout.add_argument(
        "--revoke",
        action="store_true",
        help="дополнительно отозвать токен в IAM (перестанет работать во всех harness)",
    )
    logout.set_defaults(handler=_command_logout)

    session = subcommands.add_parser(
        "session", help="обменять токен и открыть Harness Session в Control Plane"
    )
    session.add_argument("--harness", required=True, choices=SUPPORTED_HARNESS_TYPES)
    session.add_argument("--client-name", default="")
    session.add_argument("--client-version", default="")
    session.add_argument("--json", action="store_true", help="машиночитаемый вывод")
    session.set_defaults(handler=_command_session)
    return parser


def _credential_in_argv(argv: Sequence[str]) -> bool:
    return any(marker in argument for argument in argv for marker in _CREDENTIAL_MARKERS)


def main(argv: Sequence[str] | None = None, *, runtime: Runtime | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    active = runtime or Runtime(
        environ=dict(os.environ),
        cwd=Path.cwd(),
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
        store=CredentialStore(),
    )
    if _credential_in_argv(arguments):
        _fail(
            active,
            "credential_in_argv",
            "секрет передан аргументом командной строки; введите его в prompt или через stdin, "
            "а предъявленный токен считайте скомпрометированным и отзовите",
        )
        return EXIT_USAGE

    parser = build_parser()
    args = parser.parse_args(arguments)
    try:
        result = args.handler(active, args)
        return int(result)
    except (BindingError, CredentialError) as exc:
        _fail(active, exc.code, exc.message)
        return EXIT_USAGE if isinstance(exc, BindingError) else EXIT_UNAUTHENTICATED
    except RemoteError as exc:
        _fail(active, exc.code, exc.message)
        return EXIT_UNAUTHENTICATED if exc.code == "invalid_token" else EXIT_REMOTE
    except IamClientError as exc:  # pragma: no cover - защитный случай
        _fail(active, exc.code, exc.message)
        return EXIT_REMOTE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
