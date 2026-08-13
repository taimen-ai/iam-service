"""Token-first вход Codex и Claude Code через `iam auth` (IAM-4).

Проверяется полный путь локального harness: привязка репозитория, чтение
секрета без argv, хранилище с правами `0600`, введение в заблуждение
окружением, обмен на audience-bound token, разные Harness Sessions одного
Principal и отзыв при выходе.

Control Plane заменён transport-двойником, который проверяет предъявленный
access token тем же контрактом, что и настоящий resource service: RS256,
точные issuer и audience. Поэтому «токен одного audience не принимается
другим» проверяется, а не декларируется.
"""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from iam_client.cli import EXIT_OK, EXIT_REMOTE, EXIT_UNAUTHENTICATED, EXIT_USAGE, Runtime, main
from iam_client.store import CredentialStore, NullKeychain
from iam_service.app import create_app
from iam_service.config import Settings
from iam_service.tokens import verify_access_token

BOOTSTRAP = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}
ISSUER = "https://iam.example"
CONTROL_PLANE_URL = "https://control-plane.example"
AUDIENCE_SCOPES = {"control-plane": ["read", "write"], "memory-service": ["read"]}


class StubStdin(io.StringIO):
    """Неинтерактивный stdin: CLI обязан прочитать секрет из потока."""

    def isatty(self) -> bool:
        return False


class MemoryKeychain:
    """Двойник OS credential store.

    Настоящий Keychain macOS в тестах не трогаем: проверяется контракт
    приоритета хранилищ, а не поведение `security`.
    """

    def __init__(self) -> None:
        self.entries: dict[str, str] = {}

    def available(self) -> bool:
        return True

    def get(self, account: str) -> str | None:
        return self.entries.get(account)

    def set(self, account: str, token: str) -> bool:
        self.entries[account] = token
        return True

    def delete(self, account: str) -> None:
        self.entries.pop(account, None)


class FakeControlPlane:
    """Двойник Control Plane, проверяющий audience-bound token."""

    def __init__(self, public_pem: str) -> None:
        self.public_pem = public_pem
        self.sessions: list[dict[str, object]] = []
        self.rejected: list[str] = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path != "/api/v1/sessions":
            return httpx.Response(404, json={"detail": "not_found"})
        presented = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        try:
            claims = verify_access_token(
                presented, public_key=self.public_pem, issuer=ISSUER, audience="control-plane"
            )
        except jwt.PyJWTError:
            # Любой дефект токена закрывает вход одинаково: подпись, issuer,
            # audience и срок проверяются до создания session.
            self.rejected.append(presented)
            return httpx.Response(401, json={"detail": "invalid_token"})

        body = json.loads(request.content)
        harness = body.get("harness") or {}
        session = {
            "id": str(uuid.uuid4()),
            "principalId": claims["sub"],
            # Control Plane выводит control level из вида Principal, а не из
            # того, что объявил клиент.
            "controlLevel": (
                "human_operated" if claims.get("principal_type") == "human" else "connected"
            ),
            "harnessType": harness.get("type"),
            "clientName": body.get("clientName"),
            "expiresAt": (datetime.now(UTC) + timedelta(minutes=30)).isoformat(),
        }
        self.sessions.append({**session, "presentedToken": presented})
        return httpx.Response(201, json=session)


class IamHarness:
    """Поднятый IAM плюс подготовленные tenant, Principal и токен."""

    def __init__(self, client: TestClient, public_pem: str) -> None:
        self.client = client
        self.public_pem = public_pem
        self.tenant_id = ""
        self.principal_id = ""

    def transport(self) -> httpx.MockTransport:
        def handle(request: httpx.Request) -> httpx.Response:
            response = self.client.request(
                request.method,
                request.url.path,
                content=request.content,
                headers={"content-type": request.headers.get("content-type", "application/json")},
            )
            return httpx.Response(
                response.status_code,
                content=response.content,
                headers={"content-type": response.headers.get("content-type", "application/json")},
            )

        return httpx.MockTransport(handle)

    def bootstrap(self, slug: str = "tenant-a") -> str:
        tenant = self.client.post(
            "/api/v1/tenants", headers=BOOTSTRAP, json={"slug": slug, "name": "A"}
        ).json()
        self.tenant_id = tenant["id"]
        for key, scopes in AUDIENCE_SCOPES.items():
            self.client.post(
                f"/api/v1/tenants/{self.tenant_id}/audiences",
                headers=BOOTSTRAP,
                json={"key": key, "allowedScopes": scopes},
            )
        principal = self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/principals",
            headers=BOOTSTRAP,
            json={"kind": "human", "displayName": "Aleksandr Operator"},
        ).json()
        self.principal_id = principal["id"]
        self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/principals/{self.principal_id}"
            "/authentication-contexts",
            headers=BOOTSTRAP,
            json={"issuer": "https://idp.example/realms/platform", "acr": "mfa", "amr": ["otp"]},
        )
        return self.tenant_id

    def issue(
        self,
        *,
        audiences: list[str] | None = None,
        scope_ceiling: list[str] | None = None,
        name: str = "workstation",
    ) -> str:
        response = self.client.post(
            f"/api/v1/tenants/{self.tenant_id}/principals/{self.principal_id}"
            "/platform-access-tokens",
            headers={**BOOTSTRAP, "Idempotency-Key": str(uuid.uuid4())},
            json={
                "name": name,
                "audiences": audiences or ["control-plane", "memory-service"],
                "scopeCeiling": scope_ceiling or ["read", "write"],
            },
        )
        assert response.status_code == 201, response.text
        return response.json()["token"]

    def exchange(self, token: str, audience: str) -> httpx.Response:
        return self.client.post(
            "/api/v1/platform-access-tokens:exchange", json={"token": token, "audience": audience}
        )


class CliRun:
    """Результат запуска CLI: код возврата и оба потока вывода."""

    def __init__(self, code: int, stdout: str, stderr: str) -> None:
        self.code = code
        self.stdout = stdout
        self.stderr = stderr

    @property
    def output(self) -> str:
        return self.stdout + self.stderr


class Workstation:
    """Рабочая машина оператора: репозиторий, конфиг и хранилище секрета."""

    def __init__(self, root: Path, iam: IamHarness, control_plane: FakeControlPlane) -> None:
        self.root = root
        self.iam = iam
        self.control_plane = control_plane
        self.repository = root / "repository"
        self.repository.mkdir(parents=True, exist_ok=True)
        self.config_home = root / "config"
        self.environ: dict[str, str] = {"XDG_CONFIG_HOME": str(self.config_home)}
        # По умолчанию OS credential store недоступен, поэтому основной путь
        # тестов — защищённый файл `0600`.
        self.keychain: object = NullKeychain()

    def bind(self, **overrides: object) -> Path:
        document: dict[str, object] = {
            "iamUrl": ISSUER,
            "tenantId": self.iam.tenant_id,
            "audience": "control-plane",
            "controlPlaneUrl": CONTROL_PLANE_URL,
            "scopes": ["read"],
        }
        document.update(overrides)
        path = self.repository / ".iam" / "binding.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2) + "\n")
        return path

    @property
    def credentials_path(self) -> Path:
        return self.config_home / "iam" / "credentials.json"

    def store(self) -> CredentialStore:
        return CredentialStore(environ=self.environ, keychain=self.keychain)

    def run(self, *arguments: str, stdin: str = "") -> CliRun:
        stdout, stderr = io.StringIO(), io.StringIO()
        runtime = Runtime(
            environ=dict(self.environ),
            cwd=self.repository,
            stdin=StubStdin(stdin),
            stdout=stdout,
            stderr=stderr,
            store=self.store(),
            iam_transport=self.iam.transport(),
            control_plane_transport=self.control_plane.transport(),
        )
        code = main(list(arguments), runtime=runtime)
        return CliRun(code, stdout.getvalue(), stderr.getvalue())

    def repository_contents(self) -> str:
        return "\n".join(
            path.read_text(errors="ignore")
            for path in self.repository.rglob("*")
            if path.is_file()
        )


def signing_key_pair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    return private_pem, public_pem


@pytest.fixture
def workstation(tmp_path):
    private_pem, public_pem = signing_key_pair()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'iam.db'}",
        bootstrap_token="test-bootstrap-token",
        issuer=ISSUER,
        signing_private_key=private_pem,
        create_schema_on_startup=True,
    )
    with TestClient(create_app(settings)) as client:
        iam = IamHarness(client, public_pem)
        iam.bootstrap()
        yield Workstation(tmp_path, iam, FakeControlPlane(public_pem))


def login(workstation: Workstation, token: str) -> CliRun:
    return workstation.run("auth", "login", stdin=f"{token}\n")


def test_login_keeps_the_secret_out_of_repository_and_output(workstation: Workstation) -> None:
    workstation.bind()
    token = workstation.iam.issue()

    result = login(workstation, token)

    assert result.code == EXIT_OK, result.output
    # Секрет не появляется ни в выводе, ни в репозитории: наружу выходит
    # только публичный prefix.
    assert token not in result.output
    assert token.rsplit("_", 1)[1] not in result.output
    assert "iam_pat_" + token.split("_")[2] in result.stdout
    assert token not in workstation.repository_contents()
    assert not (workstation.repository / ".iam" / "credentials.json").exists()

    stored = json.loads(workstation.credentials_path.read_text())
    assert stored[f"{ISSUER}|{workstation.iam.tenant_id}"]["token"] == token
    assert workstation.credentials_path.is_relative_to(workstation.config_home)


def test_credentials_file_is_created_private(workstation: Workstation) -> None:
    workstation.bind()
    login(workstation, workstation.iam.issue())

    mode = stat.S_IMODE(workstation.credentials_path.stat().st_mode)

    assert mode == 0o600


def test_widened_credentials_file_is_refused(workstation: Workstation) -> None:
    workstation.bind()
    login(workstation, workstation.iam.issue())
    workstation.credentials_path.chmod(0o644)

    result = workstation.run("auth", "status")

    assert result.code == EXIT_UNAUTHENTICATED
    assert "credentials_file_permissions" in result.stderr


def test_os_credential_store_wins_over_file(workstation: Workstation) -> None:
    workstation.bind()
    keychain = MemoryKeychain()
    workstation.keychain = keychain
    token = workstation.iam.issue()

    result = login(workstation, token)
    status = workstation.run("auth", "status", "--json")

    assert result.code == EXIT_OK, result.output
    account = f"{ISSUER}|{workstation.iam.tenant_id}"
    assert keychain.entries[account] == token
    # Пока доступен OS credential store, секрет вообще не попадает на диск.
    assert not workstation.credentials_path.exists()
    assert json.loads(status.stdout)["credentialSource"] == "keychain"

    assert workstation.run("auth", "logout").code == EXIT_OK
    assert keychain.entries == {}


def test_token_passed_as_argument_is_refused(workstation: Workstation) -> None:
    workstation.bind()
    token = workstation.iam.issue()

    result = workstation.run("auth", "login", f"--token={token}")

    assert result.code == EXIT_USAGE
    assert "credential_in_argv" in result.stderr
    assert token not in result.output
    # Отказ наступает до любой попытки сохранить секрет.
    assert not workstation.credentials_path.exists()


def test_unbound_repository_is_denied(workstation: Workstation) -> None:
    token = workstation.iam.issue()

    result = login(workstation, token)

    assert result.code == EXIT_USAGE
    assert "repository_not_bound" in result.stderr
    assert not workstation.credentials_path.exists()


def test_binding_with_credential_material_is_rejected(workstation: Workstation) -> None:
    token = workstation.iam.issue()
    workstation.bind(token=token)

    result = workstation.run("auth", "status")

    assert result.code == EXIT_USAGE
    assert "secret_in_binding" in result.stderr
    assert token not in result.output


def test_binding_with_secret_shaped_value_is_rejected(workstation: Workstation) -> None:
    workstation.bind(note=workstation.iam.issue())

    result = workstation.run("auth", "status")

    assert result.code == EXIT_USAGE
    assert "secret_in_binding" in result.stderr


def test_login_requires_the_bound_audience(workstation: Workstation) -> None:
    workstation.bind()
    token = workstation.iam.issue(audiences=["memory-service"], scope_ceiling=["read"])

    result = login(workstation, token)

    assert result.code == EXIT_UNAUTHENTICATED
    assert "audience_not_allowed" in result.stderr
    assert not workstation.credentials_path.exists()


def test_status_reports_identity_without_the_secret(workstation: Workstation) -> None:
    workstation.bind()
    token = workstation.iam.issue()
    login(workstation, token)

    result = workstation.run("auth", "status", "--json")
    document = json.loads(result.stdout)

    assert result.code == EXIT_OK
    assert document["state"] == "active"
    assert document["principalId"] == workstation.iam.principal_id
    assert document["principalKind"] == "human"
    assert document["audiences"] == ["control-plane", "memory-service"]
    assert token not in result.output
    assert document["tokenPrefix"].endswith("…")


def test_status_without_login_is_unauthenticated(workstation: Workstation) -> None:
    workstation.bind()

    result = workstation.run("auth", "status", "--json")

    assert result.code == EXIT_UNAUTHENTICATED
    assert json.loads(result.stdout)["state"] == "logged_out"


def test_codex_and_claude_code_open_distinct_sessions_of_one_principal(
    workstation: Workstation,
) -> None:
    workstation.bind()
    login(workstation, workstation.iam.issue())

    codex = workstation.run("auth", "session", "--harness", "codex", "--json")
    claude = workstation.run("auth", "session", "--harness", "claude-code", "--json")

    assert codex.code == EXIT_OK, codex.output
    assert claude.code == EXIT_OK, claude.output
    first, second = json.loads(codex.stdout), json.loads(claude.stdout)
    # Один человек, один IAM Principal — но две разные session с настоящим
    # harness_type у каждой.
    assert first["principalId"] == second["principalId"] == workstation.iam.principal_id
    assert first["sessionId"] != second["sessionId"]
    assert {first["harnessType"], second["harnessType"]} == {"codex", "claude-code"}
    assert first["controlLevel"] == second["controlLevel"] == "human_operated"
    # Каждая session получила собственный короткоживущий credential.
    presented = {str(session["presentedToken"]) for session in workstation.control_plane.sessions}
    assert len(presented) == 2


def test_session_uses_short_lived_audience_bound_token(workstation: Workstation) -> None:
    workstation.bind()
    token = workstation.iam.issue()
    login(workstation, token)

    result = workstation.run("auth", "session", "--harness", "codex", "--json")

    assert result.code == EXIT_OK, result.output
    presented = str(workstation.control_plane.sessions[0]["presentedToken"])
    # Control Plane получил не PAT, а короткоживущий token своего audience.
    assert presented != token
    assert token not in result.output
    assert presented not in result.output
    with pytest.raises(jwt.InvalidAudienceError):
        verify_access_token(
            presented,
            public_key=workstation.iam.public_pem,
            issuer=ISSUER,
            audience="memory-service",
        )


def test_session_requires_login(workstation: Workstation) -> None:
    workstation.bind()

    result = workstation.run("auth", "session", "--harness", "codex")

    assert result.code == EXIT_UNAUTHENTICATED
    assert "not_authenticated" in result.stderr
    assert workstation.control_plane.sessions == []


def test_logout_removes_local_credential_but_keeps_token_valid(workstation: Workstation) -> None:
    workstation.bind()
    token = workstation.iam.issue()
    login(workstation, token)

    result = workstation.run("auth", "logout")

    assert result.code == EXIT_OK
    assert workstation.store().resolve(f"{ISSUER}|{workstation.iam.tenant_id}") is None
    # Без --revoke сервер токен не отзывает: он мог быть сохранён на другой машине.
    assert workstation.iam.exchange(token, "control-plane").status_code == 200


def test_logout_with_revoke_propagates_to_iam(workstation: Workstation) -> None:
    workstation.bind()
    token = workstation.iam.issue()
    login(workstation, token)

    result = workstation.run("auth", "logout", "--revoke")

    assert result.code == EXIT_OK, result.output
    assert token not in result.output
    # Отзыв немедленно закрывает и обмен, и открытие новых Harness Sessions.
    assert workstation.iam.exchange(token, "control-plane").status_code == 401
    login(workstation, token)
    denied = workstation.run("auth", "session", "--harness", "codex")
    assert denied.code == EXIT_UNAUTHENTICATED
    assert workstation.control_plane.sessions == []


def test_logout_after_remote_revocation_is_not_an_error(workstation: Workstation) -> None:
    workstation.bind()
    token = workstation.iam.issue()
    login(workstation, token)
    workstation.run("auth", "logout", "--revoke")
    login(workstation, token)

    result = workstation.run("auth", "logout", "--revoke")

    assert result.code == EXIT_OK
    assert workstation.store().resolve(f"{ISSUER}|{workstation.iam.tenant_id}") is None


def test_revoked_token_reports_invalid_status(workstation: Workstation) -> None:
    workstation.bind()
    token = workstation.iam.issue()
    login(workstation, token)
    workstation.iam.client.post(
        "/api/v1/platform-access-tokens:revoke-self", json={"token": token, "reason": "test"}
    )

    result = workstation.run("auth", "status", "--json")

    assert result.code == EXIT_UNAUTHENTICATED
    assert json.loads(result.stdout)["state"] == "invalid"


def test_environment_credential_requires_explicit_mode(workstation: Workstation) -> None:
    workstation.bind()
    token = workstation.iam.issue()
    workstation.environ["IAM_PLATFORM_ACCESS_TOKEN"] = token

    denied = workstation.run("auth", "status")
    workstation.environ["IAM_CREDENTIAL_MODE"] = "environment"
    allowed = workstation.run("auth", "status", "--json")

    assert denied.code == EXIT_UNAUTHENTICATED
    assert "environment_mode_required" in denied.stderr
    assert allowed.code == EXIT_OK
    document = json.loads(allowed.stdout)
    assert document["credentialSource"] == "environment"
    assert document["credentialLocation"] == "IAM_PLATFORM_ACCESS_TOKEN"
    assert token not in allowed.output


def test_environment_mode_does_not_write_local_copy(workstation: Workstation) -> None:
    workstation.bind()
    token = workstation.iam.issue()
    workstation.environ["IAM_PLATFORM_ACCESS_TOKEN"] = token
    workstation.environ["IAM_CREDENTIAL_MODE"] = "ci"

    result = login(workstation, token)

    assert result.code == EXIT_UNAUTHENTICATED
    assert "environment_mode_read_only" in result.stderr
    assert not workstation.credentials_path.exists()


def test_unreachable_iam_fails_closed(workstation: Workstation) -> None:
    workstation.bind()
    token = workstation.iam.issue()
    login(workstation, token)

    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("iam is down")

    stdout, stderr = io.StringIO(), io.StringIO()
    runtime = Runtime(
        environ=dict(workstation.environ),
        cwd=workstation.repository,
        stdin=StubStdin(""),
        stdout=stdout,
        stderr=stderr,
        store=workstation.store(),
        iam_transport=httpx.MockTransport(unreachable),
        control_plane_transport=workstation.control_plane.transport(),
    )

    code = main(["auth", "session", "--harness", "codex"], runtime=runtime)

    assert code == EXIT_REMOTE
    assert "iam_unreachable" in stderr.getvalue()
    assert workstation.control_plane.sessions == []


def test_iam_journal_keeps_no_credential_after_full_flow(workstation: Workstation) -> None:
    workstation.bind()
    token = workstation.iam.issue()
    login(workstation, token)
    workstation.run("auth", "session", "--harness", "codex")
    workstation.run("auth", "logout", "--revoke")

    events = workstation.iam.client.get("/api/v1/events", headers=BOOTSTRAP).text
    presented = str(workstation.control_plane.sessions[0]["presentedToken"])

    # Журнал событий описывает выпуск, обмен и отзыв, но ни PAT, ни выданный
    # access token в него не попадают.
    assert token not in events
    assert token.rsplit("_", 1)[1] not in events
    assert presented not in events
    assert "credential.revoked" in events


def test_secret_never_reaches_process_arguments(workstation: Workstation) -> None:
    """Секрет не должен появляться в argv ни на одном шаге сценария."""

    workstation.bind()
    token = workstation.iam.issue()
    recorded: list[list[str]] = []
    original = sys.argv

    def record(*arguments: str, stdin: str = "") -> CliRun:
        sys.argv = ["iam", *arguments]
        recorded.append(list(sys.argv))
        try:
            return workstation.run(*arguments, stdin=stdin)
        finally:
            sys.argv = original

    record("auth", "login", stdin=f"{token}\n")
    record("auth", "status")
    record("auth", "session", "--harness", "claude-code")
    record("auth", "logout", "--revoke")

    assert all(token not in " ".join(arguments) for arguments in recorded)
    assert os.environ.get("IAM_PLATFORM_ACCESS_TOKEN") is None
