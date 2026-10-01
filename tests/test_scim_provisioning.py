"""SCIM 2.0 provisioning для IAM Service (IAM-5).

Тесты работают на изолированной sqlite-базе и не поднимают ни Keycloak, ни
внешний SCIM-клиент: upstream-драйвер подменяется фиктивным транспортом, а
федеративный вход — локальным OIDC issuer из `conftest`. Проверяется весь
negative matrix: чужой credential, человеческий token, повторный create,
запрет второго authoritative source на population, изоляция tenant,
деактивация с отзывом credentials, удаление только своих mappings, деградация
upstream и устаревание источника.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from iam_service.app import create_app
from iam_service.config import Settings
from iam_service.models import ExternalIdentity, Group, GroupMember, OutboxEvent, Principal
from iam_service.scim.driver import UpstreamResponse
from iam_service.scim.models import ProvisioningSource, ScimGroup, ScimUser
from iam_service.tokens import TokenIssuer

BOOTSTRAP = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}
ISSUER = "https://iam.example"
SCIM_AUDIENCE = "iam-scim"
SCIM_SCOPE = "scim:write"
EXTERNAL_ID_CLAIM = "employee_id"


class FakeUpstream:
    """Keycloak с управляемым поведением обеих дорог записи."""

    def __init__(self, *, scim_status: int = 201, admin_status: int = 201) -> None:
        self.scim_status = scim_status
        self.admin_status = admin_status
        self.calls: list[tuple[str, str]] = []

    async def send(self, method: str, url: str, *, json=None) -> UpstreamResponse:
        road = "scim" if "/scim/v2/" in url else "admin"
        self.calls.append((road, method))
        if road == "scim":
            return UpstreamResponse(status_code=self.scim_status, payload={"id": "kc-scim-user"})
        return UpstreamResponse(
            status_code=self.admin_status,
            payload={},
            location="https://kc.example/admin/realms/platform/users/kc-admin-user",
        )

    @property
    def roads(self) -> list[str]:
        return [road for road, _ in self.calls]


class Harness:
    """Сервис плюс прямой доступ к базе для подготовки и проверки состояния."""

    def __init__(self, client: TestClient, database_path, private_pem: str) -> None:
        self.client = client
        self.database_path = database_path
        self.private_pem = private_pem
        self.engine = create_engine(f"sqlite:///{database_path}")
        self.tenant_id = ""
        self.token = ""

    def session(self) -> Session:
        return Session(self.engine)

    # --- подготовка ----------------------------------------------------

    def create_tenant(self, slug: str) -> str:
        tenant = self.client.post(
            "/api/v1/tenants", headers=BOOTSTRAP, json={"slug": slug, "name": slug}
        ).json()
        tenant_id = tenant["id"]
        for key, scopes in {
            SCIM_AUDIENCE: [SCIM_SCOPE],
            "control-plane": ["read"],
        }.items():
            response = self.client.post(
                f"/api/v1/tenants/{tenant_id}/audiences",
                headers=BOOTSTRAP,
                json={"key": key, "allowedScopes": scopes},
            )
            assert response.status_code == 201, response.text
        return tenant_id

    def create_identity_provider(
        self,
        tenant_id: str,
        *,
        key: str,
        issuer: str,
        audience: str,
        jwks_uri: str,
        lifecycle_profile: str = "managed",
    ) -> str:
        response = self.client.post(
            f"/api/v1/tenants/{tenant_id}/identity-providers",
            headers=BOOTSTRAP,
            json={
                "key": key,
                "issuer": issuer,
                "audience": audience,
                "jwksUri": jwks_uri,
                "externalIdClaim": EXTERNAL_ID_CLAIM,
                "lifecycleProfile": lifecycle_profile,
            },
        )
        assert response.status_code == 201, response.text
        return response.json()["id"]

    def service_identity(self, tenant_id: str, *, name: str) -> tuple[str, str]:
        """Confidential service identity SCIM-клиента и её access token."""

        created = self.client.post(
            f"/api/v1/tenants/{tenant_id}/service-accounts",
            headers=BOOTSTRAP,
            json={
                "displayName": name,
                "audiences": [SCIM_AUDIENCE],
                "scopeCeiling": [SCIM_SCOPE],
            },
        )
        assert created.status_code == 201, created.text
        account = created.json()
        exchanged = self.client.post(
            "/api/v1/tokens/exchange",
            json={
                "clientId": account["clientId"],
                "clientSecret": account["clientSecret"],
                "audience": SCIM_AUDIENCE,
                "scopes": [SCIM_SCOPE],
            },
        )
        assert exchanged.status_code == 200, exchanged.text
        return account["principalId"], exchanged.json()["accessToken"]

    def register_source(self, tenant_id: str, **body):
        return self.client.post(
            f"/api/v1/tenants/{tenant_id}/provisioning-sources", headers=BOOTSTRAP, json=body
        )

    def forge_token(self, *, principal_id: str, tenant_id: str, principal_type: str) -> str:
        """Токен нужного вида, выпущенный тем же ключом, что и IAM."""

        return TokenIssuer(
            issuer=ISSUER, private_key=self.private_pem, key_id="local-dev", ttl_seconds=300
        ).issue(
            subject=uuid.UUID(principal_id),
            tenant_id=uuid.UUID(tenant_id),
            audience=SCIM_AUDIENCE,
            scopes=[SCIM_SCOPE],
            credential_id=uuid.uuid4(),
            principal_type=principal_type,
        )

    # --- SCIM ----------------------------------------------------------

    def scim(self, method: str, path: str, *, token: str | None = None, **kwargs):
        headers = {"Authorization": f"Bearer {token or self.token}", **kwargs.pop("headers", {})}
        return self.client.request(method, path, headers=headers, **kwargs)

    def create_user(self, *, external_id: str, user_name: str, active: bool = True, **kwargs):
        return self.scim(
            "POST",
            "/scim/v2/Users",
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "externalId": external_id,
                "userName": user_name,
                "displayName": user_name,
                "active": active,
            },
            **kwargs,
        )

    def create_group(self, *, display_name: str, members: list[str] | None = None, **kwargs):
        return self.scim(
            "POST",
            "/scim/v2/Groups",
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": display_name,
                "members": [{"value": member} for member in members or []],
            },
            **kwargs,
        )

    def patch(self, path: str, operations: list[dict], **kwargs):
        return self.scim(
            "PATCH",
            path,
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": operations,
            },
            **kwargs,
        )

    def events(self, type_: str) -> list[dict]:
        with self.session() as session:
            return [
                {"type": row.type, "payload": row.payload}
                for row in session.scalars(select(OutboxEvent).where(OutboxEvent.type == type_))
            ]


@pytest.fixture
def upstream() -> FakeUpstream:
    return FakeUpstream()


@pytest.fixture
def harness(tmp_path, idp, fetcher, upstream):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'iam.db'}",
        bootstrap_token="test-bootstrap-token",
        issuer=ISSUER,
        signing_private_key=private_pem,
        create_schema_on_startup=True,
    )
    app = create_app(settings, jwks_fetcher=fetcher, upstream_transport=upstream)
    with TestClient(app) as client:
        harness = Harness(client, tmp_path / "iam.db", private_pem)
        harness.tenant_id = harness.create_tenant("tenant-a")
        harness.create_identity_provider(
            harness.tenant_id,
            key="workforce",
            issuer=idp.issuer,
            audience=idp.audience,
            jwks_uri=idp.jwks_uri,
        )
        harness.service_principal_id, harness.token = harness.service_identity(
            harness.tenant_id, name="hr-scim-client"
        )
        registered = harness.register_source(
            harness.tenant_id,
            key="workforce-scim",
            kind="scim",
            identityProvider="workforce",
            servicePrincipalId=harness.service_principal_id,
        )
        assert registered.status_code == 201, registered.text
        harness.source_id = registered.json()["id"]
        yield harness


def test_scim_rejects_anything_but_a_confidential_service_identity(harness: Harness) -> None:
    anonymous = harness.client.get("/scim/v2/Users")
    human = harness.scim(
        "GET",
        "/scim/v2/Users",
        token=harness.forge_token(
            principal_id=harness.service_principal_id,
            tenant_id=harness.tenant_id,
            principal_type="human",
        ),
    )
    stranger_id, stranger_token = harness.service_identity(harness.tenant_id, name="other-client")
    stranger = harness.scim("GET", "/scim/v2/Users", token=stranger_token)

    assert anonymous.status_code == 401
    # Отказ приходит SCIM-документом, а не структурой FastAPI.
    assert anonymous.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert anonymous.headers["content-type"].startswith("application/scim+json")
    # SCIM управляет чужим lifecycle и не является способом входа человека.
    assert human.status_code == 403
    assert "service identity" in human.json()["detail"]
    # Service identity без зарегистрированного source ничего не видит.
    assert stranger.status_code == 403
    assert stranger_id != harness.service_principal_id


def test_provisioning_creates_identity_without_entitlement_or_local_grants(
    harness: Harness, upstream: FakeUpstream
) -> None:
    created = harness.create_user(external_id="hr-1", user_name="ada@example.com")

    assert created.status_code == 201, created.text
    body = created.json()
    assert body["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
    assert body["externalId"] == "hr-1"
    assert body["active"] is True
    # Provisioning не выдаёт ни групп, ни лицензий: он только заводит identity.
    assert body["groups"] == []
    assert created.headers["etag"] == 'W/"1"'
    # Режим `off`: upstream не трогается, IAM ведёт собственную проекцию.
    assert upstream.calls == []

    with harness.session() as session:
        user = session.scalars(select(ScimUser)).one()
        principal = session.get(Principal, user.principal_id)
        identity = session.get(ExternalIdentity, user.external_identity_id)
        assert principal.kind == "human" and principal.status == "active"
        assert identity.source == "provisioned"
        assert identity.external_id == "hr-1"
        assert identity.provisioning_source_id == user.provisioning_source_id
        assert session.scalars(select(GroupMember)).all() == []

    # В journal уходят только стабильные идентификаторы, без userName.
    payloads = str(harness.events("scim_user.provisioned"))
    assert "ada@example.com" not in payloads
    assert body["id"] in payloads


def test_repeated_create_does_not_produce_a_second_principal(harness: Harness) -> None:
    first = harness.create_user(external_id="hr-1", user_name="ada@example.com")
    replay = harness.create_user(external_id="hr-1", user_name="ada@example.com")
    renamed = harness.create_user(external_id="hr-2", user_name="ada@example.com")

    assert first.status_code == 201
    assert replay.status_code == 409
    assert replay.json()["scimType"] == "uniqueness"
    # Один externalId и один userName остаются одной identity.
    assert renamed.status_code == 409
    with harness.session() as session:
        assert len(session.scalars(select(ScimUser)).all()) == 1


def test_filtering_and_pagination_are_bounded(harness: Harness) -> None:
    for index in range(3):
        assert (
            harness.create_user(
                external_id=f"hr-{index}", user_name=f"user{index}@example.com"
            ).status_code
            == 201
        )

    filtered = harness.scim("GET", '/scim/v2/Users?filter=userName eq "user1@example.com"')
    combined = harness.scim("GET", '/scim/v2/Users?filter=externalId eq "hr-1" and active eq true')
    paged = harness.scim("GET", "/scim/v2/Users?startIndex=2&count=1")
    unsupported = harness.scim("GET", '/scim/v2/Users?filter=userName co "user"')

    assert filtered.json()["totalResults"] == 1
    assert filtered.json()["Resources"][0]["externalId"] == "hr-1"
    assert combined.json()["totalResults"] == 1
    assert paged.json()["totalResults"] == 3
    assert paged.json()["itemsPerPage"] == 1
    assert paged.json()["Resources"][0]["externalId"] == "hr-1"
    # Неподдерживаемый оператор не расширяет выборку молча.
    assert unsupported.status_code == 400
    assert unsupported.json()["scimType"] == "invalidFilter"


def test_deactivation_disables_principal_and_revokes_credentials(harness: Harness) -> None:
    user = harness.create_user(external_id="hr-1", user_name="ada@example.com").json()
    principal_id = str(harness.session().scalars(select(ScimUser)).one().principal_id)
    authenticated = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{principal_id}/authentication-contexts",
        headers=BOOTSTRAP,
        json={"issuer": ISSUER, "acr": "urn:test:silver", "amr": ["pwd"]},
    )
    assert authenticated.status_code == 201, authenticated.text
    issued = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/principals/{principal_id}/platform-access-tokens",
        headers={**BOOTSTRAP, "Idempotency-Key": str(uuid.uuid4())},
        json={"name": "cli", "audiences": ["control-plane"], "scopeCeiling": ["read"]},
    )
    assert issued.status_code == 201, issued.text
    pat = issued.json()["token"]

    disabled = harness.patch(
        f"/scim/v2/Users/{user['id']}", [{"op": "replace", "path": "active", "value": False}]
    )
    exchange = harness.client.post(
        "/api/v1/platform-access-tokens:exchange",
        json={"token": pat, "audience": "control-plane", "scopes": []},
    )

    assert disabled.status_code == 200
    assert disabled.json()["active"] is False
    assert disabled.headers["etag"] == 'W/"2"'
    # Отключение в кадровой системе немедленно закрывает выданные credentials.
    assert exchange.status_code == 401
    assert exchange.json()["detail"] == "invalid_token"
    with harness.session() as session:
        assert session.get(Principal, uuid.UUID(principal_id)).status == "disabled"


def test_replace_is_guarded_by_version_and_keeps_external_id_immutable(harness: Harness) -> None:
    user = harness.create_user(external_id="hr-1", user_name="ada@example.com").json()
    path = f"/scim/v2/Users/{user['id']}"
    body = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "externalId": "hr-1",
        "userName": "ada.lovelace@example.com",
        "displayName": "Ada Lovelace",
        "active": True,
    }

    stale = harness.scim("PUT", path, json=body, headers={"If-Match": 'W/"7"'})
    replaced = harness.scim("PUT", path, json=body, headers={"If-Match": 'W/"1"'})
    repeated = harness.scim("PUT", path, json=body, headers={"If-Match": 'W/"2"'})
    rekeyed = harness.scim("PUT", path, json={**body, "externalId": "hr-9"})

    # Второй проход reconciliation не затирает результат первого.
    assert stale.status_code == 412
    assert replaced.status_code == 200
    assert replaced.json()["userName"] == "ada.lovelace@example.com"
    assert replaced.headers["etag"] == 'W/"2"'
    # Повтор того же состояния не считается изменением и не двигает версию.
    assert repeated.headers["etag"] == 'W/"2"'
    # Стабильный внешний идентификатор не переписывается через PUT.
    assert rekeyed.status_code == 400
    assert rekeyed.json()["scimType"] == "mutability"


def test_deprovisioning_removes_only_provisioned_mappings(harness: Harness) -> None:
    user = harness.create_user(external_id="hr-1", user_name="ada@example.com").json()
    principal_id = str(harness.session().scalars(select(ScimUser)).one().principal_id)
    group = harness.create_group(display_name="Platform Engineering", members=[user["id"]]).json()
    local_group = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/groups",
        headers=BOOTSTRAP,
        json={"key": "local-oncall", "name": "Local oncall"},
    ).json()
    local_membership = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/groups/{local_group['id']}/members",
        headers=BOOTSTRAP,
        json={"principalId": principal_id},
    )
    assert local_membership.status_code == 201, local_membership.text
    with harness.session() as session:
        provisioned_group_id = str(session.scalars(select(ScimGroup)).one().group_id)
    manual_into_provisioned = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/groups/{provisioned_group_id}/members",
        headers=BOOTSTRAP,
        json={"principalId": principal_id},
    )

    assert (
        harness.scim("GET", f"/scim/v2/Groups/{group['id']}").json()["members"][0]["value"]
        == user["id"]
    )
    # Состав provisioned-группы задаёт source, а не локальный администратор.
    assert manual_into_provisioned.status_code == 409
    assert manual_into_provisioned.json()["detail"] == "group_is_federated"

    removed = harness.scim("DELETE", f"/scim/v2/Users/{user['id']}")

    assert removed.status_code == 204
    assert harness.scim("GET", f"/scim/v2/Users/{user['id']}").status_code == 404
    with harness.session() as session:
        memberships = session.scalars(select(GroupMember)).all()
        # Осталось ровно локальное членство: provisioning отзывает только своё.
        assert [member.source for member in memberships] == ["local"]
        assert str(memberships[0].group_id) == local_group["id"]
        assert session.get(Principal, uuid.UUID(principal_id)).status == "disabled"


def test_group_membership_is_idempotent(harness: Harness) -> None:
    user = harness.create_user(external_id="hr-1", user_name="ada@example.com").json()
    group = harness.create_group(display_name="Platform Engineering").json()
    path = f"/scim/v2/Groups/{group['id']}"

    added = harness.patch(
        path, [{"op": "add", "path": "members", "value": [{"value": user["id"]}]}]
    )
    replayed = harness.patch(
        path, [{"op": "add", "path": "members", "value": [{"value": user["id"]}]}]
    )
    removed = harness.patch(path, [{"op": "remove", "path": f'members[value eq "{user["id"]}"]'}])
    removed_again = harness.patch(
        path, [{"op": "remove", "path": f'members[value eq "{user["id"]}"]'}]
    )

    assert [entry["value"] for entry in added.json()["members"]] == [user["id"]]
    # Повтор не создаёт второе членство и не меняет версию ресурса.
    assert replayed.json()["members"] == added.json()["members"]
    assert replayed.json()["meta"]["version"] == added.json()["meta"]["version"]
    assert removed.json()["members"] == []
    assert removed_again.json()["meta"]["version"] == removed.json()["meta"]["version"]


def test_scim_cannot_create_the_people_admin_group(harness: Harness) -> None:
    """Группу администраторов людей заводит только bootstrap (ADR-0002)."""

    refused = harness.create_group(display_name="People Admins")

    assert refused.status_code == 409
    with harness.session() as session:
        assert session.scalar(select(Group).where(Group.key == "people-admins")) is None


def test_scim_cannot_create_the_fleet_admin_group(harness: Harness) -> None:
    """Группы всех привилегированных scope заводит только bootstrap (ADR-0003)."""

    refused = harness.create_group(display_name="Fleet Admins")

    assert refused.status_code == 409
    with harness.session() as session:
        assert session.scalar(select(Group).where(Group.key == "fleet-admins")) is None


def test_one_population_has_a_single_authoritative_source(harness: Harness, idp) -> None:
    harness.create_identity_provider(
        harness.tenant_id,
        key="directory",
        issuer="https://ldap-broker.example/realms/dir",
        audience="iam-service",
        jwks_uri="https://ldap-broker.example/certs",
        lifecycle_profile="read_only",
    )
    principal_id, _ = harness.service_identity(harness.tenant_id, name="second-client")

    directory_owned = harness.register_source(
        harness.tenant_id,
        key="directory-scim",
        kind="scim",
        identityProvider="directory",
        servicePrincipalId=principal_id,
    )
    second_source = harness.register_source(
        harness.tenant_id,
        key="workforce-ldap",
        kind="ldap",
        identityProvider="workforce",
    )

    # READ_ONLY профиль означает, что lifecycle ведёт каталог.
    assert directory_owned.status_code == 409
    assert directory_owned.json()["detail"] == "population_managed_by_directory"
    # Вторая запись в ту же population не регистрируется вовсе.
    assert second_source.status_code == 409
    assert second_source.json()["detail"] == "provisioning_source_exists"


def test_tenant_isolation(harness: Harness, idp) -> None:
    user = harness.create_user(external_id="hr-1", user_name="ada@example.com").json()
    other_tenant = harness.create_tenant("tenant-b")
    harness.create_identity_provider(
        other_tenant,
        key="workforce",
        issuer="https://idp.example/realms/other",
        audience="iam-service",
        jwks_uri="https://idp.example/realms/other/certs",
    )
    principal_id, token = harness.service_identity(other_tenant, name="tenant-b-client")
    assert (
        harness.register_source(
            other_tenant,
            key="workforce-scim",
            kind="scim",
            identityProvider="workforce",
            servicePrincipalId=principal_id,
        ).status_code
        == 201
    )

    listed = harness.scim("GET", "/scim/v2/Users", token=token)
    fetched = harness.scim("GET", f"/scim/v2/Users/{user['id']}", token=token)

    assert listed.json()["totalResults"] == 0
    assert fetched.status_code == 404


def test_upstream_driver_falls_back_to_admin_api_and_fails_closed(tmp_path, idp, fetcher) -> None:
    upstream = FakeUpstream(scim_status=501)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'driver.db'}",
        bootstrap_token="test-bootstrap-token",
        issuer=ISSUER,
        signing_private_key=private_pem,
        create_schema_on_startup=True,
    )
    with TestClient(
        create_app(settings, jwks_fetcher=fetcher, upstream_transport=upstream)
    ) as client:
        harness = Harness(client, tmp_path / "driver.db", private_pem)
        harness.tenant_id = harness.create_tenant("tenant-a")
        harness.create_identity_provider(
            harness.tenant_id,
            key="workforce",
            issuer=idp.issuer,
            audience=idp.audience,
            jwks_uri=idp.jwks_uri,
        )
        principal_id, harness.token = harness.service_identity(
            harness.tenant_id, name="hr-scim-client"
        )
        assert (
            harness.register_source(
                harness.tenant_id,
                key="workforce-scim",
                kind="scim",
                identityProvider="workforce",
                servicePrincipalId=principal_id,
                upstreamMode="auto",
                upstreamBaseUrl="https://kc.example",
                upstreamRealm="platform",
            ).status_code
            == 201
        )

        created = harness.create_user(external_id="hr-1", user_name="ada@example.com")

        assert created.status_code == 201, created.text
        # Native SCIM API выключен — запись уходит стабильным Admin API.
        assert upstream.roads == ["scim", "admin"]
        with harness.session() as session:
            assert session.scalars(select(ScimUser)).one().upstream_user_id == "kc-admin-user"

        upstream.admin_status = 503
        degraded = harness.create_user(external_id="hr-2", user_name="grace@example.com")

        # Обе дороги недоступны — fail closed, локальная проекция не расходится.
        assert degraded.status_code == 502
        with harness.session() as session:
            assert len(session.scalars(select(ScimUser)).all()) == 1
            humans = session.scalars(select(Principal).where(Principal.kind == "human")).all()
            assert len(humans) == 1


def test_stale_source_is_reported_and_alerted_once(harness: Harness) -> None:
    assert harness.create_user(external_id="hr-1", user_name="ada@example.com").status_code == 201
    with harness.session() as session:
        source = session.scalars(select(ProvisioningSource)).one()
        source.last_sync_at = datetime.now(UTC) - timedelta(seconds=source.stale_after_seconds + 60)
        session.commit()

    first = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/provisioning-sources", headers=BOOTSTRAP
    )
    second = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/provisioning-sources", headers=BOOTSTRAP
    )

    assert first.json()[0]["stale"] is True
    assert second.json()[0]["stale"] is True
    # Событие поднимается один раз на эпизод, а не на каждое чтение.
    assert len(harness.events("provisioning_source.stale")) == 1

    resumed = harness.create_user(external_id="hr-2", user_name="grace@example.com")
    after = harness.client.get(
        f"/api/v1/tenants/{harness.tenant_id}/provisioning-sources", headers=BOOTSTRAP
    )

    assert resumed.status_code == 201
    assert after.json()[0]["stale"] is False


def test_federated_login_adopts_the_provisioned_identity(harness: Harness, idp) -> None:
    """Один issuer+subject не порождает второго Principal.

    Provisioning заводит identity до первого входа, поэтому реального OIDC
    `sub` ещё нет. При входе federation находит запись по стабильному external
    ID и заменяет placeholder, а не создаёт вторую identity.
    """

    harness.create_user(external_id="hr-1", user_name="ada@example.com")
    with harness.session() as session:
        provisioned = session.scalars(select(ExternalIdentity)).one()
        assert provisioned.subject.startswith("urn:iam:scim:")
        principal_id = provisioned.principal_id

    authenticated = harness.client.post(
        f"/api/v1/tenants/{harness.tenant_id}/federation:authenticate",
        json={
            "identityProvider": "workforce",
            "token": idp.token(subject="keycloak-uuid", claims={EXTERNAL_ID_CLAIM: "hr-1"}),
        },
    )

    assert authenticated.status_code == 200, authenticated.text
    assert authenticated.json()["principalId"] == str(principal_id)
    with harness.session() as session:
        identity = session.scalars(select(ExternalIdentity)).one()
        assert identity.subject == "keycloak-uuid"
        assert identity.principal_id == principal_id
        # Второй Principal не появился: SCIM-запись и вход — одна identity.
        assert len(session.scalars(select(Principal).where(Principal.kind == "human")).all()) == 1
