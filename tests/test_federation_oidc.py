from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from conftest import FakeFetcher, FakeIdentityProvider
from iam_service.app import create_app
from iam_service.config import Settings

BOOTSTRAP = {"X-IAM-Bootstrap-Token": "test-bootstrap-token"}


def build_client(tmp_path, fetcher: FakeFetcher) -> TestClient:
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'iam.db'}",
        bootstrap_token="test-bootstrap-token",
        create_schema_on_startup=True,
    )
    return TestClient(create_app(settings, jwks_fetcher=fetcher))


def register_tenant_and_provider(
    client: TestClient, idp: FakeIdentityProvider, **overrides: Any
) -> tuple[str, dict[str, Any]]:
    tenant = client.post(
        "/api/v1/tenants", headers=BOOTSTRAP, json={"slug": "tenant-a", "name": "A"}
    ).json()
    body: dict[str, Any] = {
        "key": "keycloak",
        "issuer": idp.issuer,
        "audience": idp.audience,
        "groupMappings": {"platform-operators": "operators"},
    }
    body.update(overrides)
    provider = client.post(
        f"/api/v1/tenants/{tenant['id']}/identity-providers", headers=BOOTSTRAP, json=body
    )
    assert provider.status_code == 201, provider.text
    return tenant["id"], provider.json()


def authenticate(client: TestClient, tenant_id: str, token: str, provider: str = "keycloak"):
    return client.post(
        f"/api/v1/tenants/{tenant_id}/federation:authenticate",
        json={"identityProvider": provider, "token": token},
    )


def test_federation_links_principal_and_projects_only_allowlisted_groups(
    tmp_path, idp: FakeIdentityProvider, fetcher: FakeFetcher
) -> None:
    with build_client(tmp_path, fetcher) as client:
        tenant_id, _ = register_tenant_and_provider(client, idp)
        token = idp.token(claims={"groups": ["/platform-operators", "/finance-admins"], "acr": "1"})
        first = authenticate(client, tenant_id, token)
        second = authenticate(client, tenant_id, token)
        events = client.get("/api/v1/events", headers=BOOTSTRAP).json()["items"]

    assert first.status_code == 200, first.text
    assert second.status_code == 200
    assert first.json()["principalId"] == second.json()["principalId"]
    assert first.json()["groups"] == ["operators"]
    assert first.json()["authenticationContext"]["acr"] == "1"
    assert first.json()["identityProviderStale"] is False

    types = [event["type"] for event in events]
    assert types.count("principal.created") == 1
    assert types.count("group_membership.added") == 1
    # federation подтверждает identity, но не выдаёт лицензию и не создаёт
    # service-local credential: ни audience, ни service account не появляются.
    assert "audience.created" not in types
    assert "service_account.created" not in types
    assert "accessToken" not in first.text


def test_federation_only_reaches_the_idp_when_the_jwks_cache_expires(
    tmp_path, idp: FakeIdentityProvider, fetcher: FakeFetcher
) -> None:
    with build_client(tmp_path, fetcher) as client:
        tenant_id, _ = register_tenant_and_provider(client, idp)
        token = idp.token()
        authenticate(client, tenant_id, token)
        calls_after_first = len(fetcher.calls)
        authenticate(client, tenant_id, token)

    assert fetcher.calls[:2] == [idp.discovery_uri, idp.jwks_uri]
    assert len(fetcher.calls) == calls_after_first


@pytest.mark.parametrize(
    ("token_kwargs", "expected_status", "expected_detail"),
    [
        ({"issuer": "https://attacker.example"}, 401, "invalid_issuer"),
        ({"audience": "another-service"}, 401, "invalid_audience"),
        ({"sign_with_foreign_key": True}, 401, "invalid_signature"),
        ({"algorithm": "HS256"}, 401, "unsupported_algorithm"),
        ({"key_id": "rotated-away"}, 401, "unknown_signing_key"),
        ({"expires_in": -60}, 401, "token_expired"),
    ],
)
def test_untrusted_upstream_tokens_are_rejected(
    tmp_path,
    idp: FakeIdentityProvider,
    fetcher: FakeFetcher,
    token_kwargs: dict[str, Any],
    expected_status: int,
    expected_detail: str,
) -> None:
    with build_client(tmp_path, fetcher) as client:
        tenant_id, _ = register_tenant_and_provider(client, idp)
        response = authenticate(client, tenant_id, idp.token(**token_kwargs))
        events = client.get("/api/v1/events", headers=BOOTSTRAP).json()["items"]

    assert response.status_code == expected_status
    assert response.json()["detail"] == expected_detail
    assert [event["type"] for event in events] == ["tenant.created", "identity_provider.registered"]


def test_password_credentials_are_not_part_of_the_federation_contract(
    tmp_path, idp: FakeIdentityProvider, fetcher: FakeFetcher
) -> None:
    with build_client(tmp_path, fetcher) as client:
        tenant_id, _ = register_tenant_and_provider(client, idp)
        with_password = client.post(
            f"/api/v1/tenants/{tenant_id}/federation:authenticate",
            json={
                "identityProvider": "keycloak",
                "username": "alice",
                "password": "ldap-secret-value",
            },
        )
        token_plus_password = client.post(
            f"/api/v1/tenants/{tenant_id}/federation:authenticate",
            json={
                "identityProvider": "keycloak",
                "token": idp.token(),
                "password": "ldap-secret-value",
            },
        )
        events = client.get("/api/v1/events", headers=BOOTSTRAP).text

    assert with_password.status_code == 422
    assert token_plus_password.status_code == 422
    assert "ldap-secret-value" not in events


def test_stable_external_id_keeps_one_principal_per_upstream_identity(
    tmp_path, idp: FakeIdentityProvider, fetcher: FakeFetcher
) -> None:
    with build_client(tmp_path, fetcher) as client:
        tenant_id, _ = register_tenant_and_provider(client, idp, externalIdClaim="ldap_id")
        first_person = authenticate(
            client,
            tenant_id,
            idp.token(subject="keycloak-subject-1", claims={"ldap_id": "ldap-entry-uuid-1"}),
        )
        second_person = authenticate(
            client,
            tenant_id,
            idp.token(subject="keycloak-subject-2", claims={"ldap_id": "ldap-entry-uuid-2"}),
        )
        # Keycloak пересоздал пользователя из LDAP: subject новый, стабильный
        # LDAP ID прежний — это тот же Principal, а не третий.
        rotated_subject = authenticate(
            client,
            tenant_id,
            idp.token(subject="keycloak-subject-3", claims={"ldap_id": "ldap-entry-uuid-1"}),
        )
        # Один стабильный external ID не может принадлежать двум Principals:
        # рассинхрон закрывается, а не переносит identity молча.
        conflicting_external_id = authenticate(
            client,
            tenant_id,
            idp.token(subject="keycloak-subject-3", claims={"ldap_id": "ldap-entry-uuid-2"}),
        )
        events = client.get("/api/v1/events", headers=BOOTSTRAP).json()["items"]

    assert first_person.status_code == 200
    assert second_person.status_code == 200
    assert second_person.json()["principalId"] != first_person.json()["principalId"]
    assert rotated_subject.status_code == 200
    assert rotated_subject.json()["principalId"] == first_person.json()["principalId"]
    assert conflicting_external_id.status_code == 409
    assert conflicting_external_id.json()["detail"] == "external_identity_conflict"
    assert [event["type"] for event in events].count("principal.created") == 2


def test_federation_does_not_extend_membership_to_another_tenant(
    tmp_path, idp: FakeIdentityProvider, fetcher: FakeFetcher
) -> None:
    with build_client(tmp_path, fetcher) as client:
        tenant_id, _ = register_tenant_and_provider(client, idp)
        neighbour = client.post(
            "/api/v1/tenants", headers=BOOTSTRAP, json={"slug": "tenant-b", "name": "B"}
        ).json()
        client.post(
            f"/api/v1/tenants/{neighbour['id']}/identity-providers",
            headers=BOOTSTRAP,
            json={"key": "keycloak", "issuer": idp.issuer, "audience": idp.audience},
        )
        token = idp.token(subject="shared-subject")
        home = authenticate(client, tenant_id, token)
        # Тот же upstream token, предъявленный чужому Tenant, не создаёт там
        # членство: federation подтверждает identity, но не выдаёт доступ.
        neighbouring = authenticate(client, neighbour["id"], token)

    assert home.status_code == 200
    assert neighbouring.status_code == 403
    assert neighbouring.json()["detail"] == "principal_not_in_tenant"


def test_step_up_is_required_when_the_provider_demands_mfa(
    tmp_path, idp: FakeIdentityProvider, fetcher: FakeFetcher
) -> None:
    with build_client(tmp_path, fetcher) as client:
        tenant_id, _ = register_tenant_and_provider(
            client, idp, requiredAcrValues=["mfa"], requiredAmrValues=["otp"]
        )
        single_factor = authenticate(client, tenant_id, idp.token(claims={"acr": "1"}))
        wrong_factor = authenticate(
            client, tenant_id, idp.token(claims={"acr": "mfa", "amr": ["pwd"]})
        )
        stepped_up = authenticate(
            client,
            tenant_id,
            idp.token(claims={"acr": "mfa", "amr": ["pwd", "otp"], "auth_time": 1_760_000_000}),
        )

    assert single_factor.status_code == 403
    assert single_factor.json()["detail"] == "step_up_required"
    assert wrong_factor.status_code == 403
    assert stepped_up.status_code == 200
    assert stepped_up.json()["authenticationContext"]["amr"] == ["pwd", "otp"]
    assert stepped_up.json()["authenticationContext"]["authTime"] is not None
