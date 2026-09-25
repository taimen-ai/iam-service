# IAM Service

*English. Russian version: [README.ru.md](README.ru.md)*

A product-neutral backend of unified identity for independently shipped and
licensed resource services. IAM Service confirms the Principal and the Tenant,
issues short-lived audience-specific credentials and publishes identity
events. It does not store licences and does not replace the domain
authorization of Control Plane, Memory Service or any other product.

The canonical boundaries are defined by the top-level ADR-0013.

## What the foundation implements

- Tenant and Tenant Membership;
- Principals of kinds `human`, `agent`, `service_account`, `workload`;
- external identity with a globally unique `issuer + subject` pair;
- tenant-scoped global Groups and memberships;
- tenant-scoped Audience registry and allowlisted scopes;
- service account secret with an Argon2 hash and one-time display;
- RS256 access token with an exact audience, Tenant and scope ceiling;
- JWKS endpoint for local verification by resource services;
- revocation of a service account and termination of new token exchange;
- append-only event journal via a transactional outbox;
- a separate audit without token/secret/subject payload;
- Alembic migration and Docker Compose with its own PostgreSQL.

## Identity federation

- registry of upstream identity providers: issuer, expected audience, claim names,
  group allowlist and lifecycle profile;
- OIDC discovery and JWKS with a cache, a bounded stale window and fail-closed
  after it;
- strict verification of the upstream token: signature, exact issuer, exact
  audience, time claims; symmetric algorithms and `none` are rejected;
- linking by `issuer + subject` cross-checked against a stable external ID
  (for LDAP — `entryUUID`), so that one upstream identity does not end up with
  two Principals;
- authentication context `acr`/`amr`/`auth_time` and step-up: an insufficient
  context closes the login rather than lowering the requirements;
- projection of upstream groups onto IAM Groups strictly by allowlist mappings;
- reference Keycloak deployment with LDAP User Federation in `deploy/keycloak`.

Federation confirms identity and the group projection. It does not grant a
Product Entitlement or a service-local role: access to a resource still requires
separate entitlement and domain-policy decisions.

### `federation:exchange` — login and credential in a single request

`federation:authenticate` only confirms identity. For a human in a browser that
is not enough: the web console reaches a resource service through a gateway, and
the gateway holds only the user's upstream token — the Platform Access Token is
designed for a local harness and does not pass through a web session, while
keeping a shared service credential in the gateway would mean losing the human
themselves from the audit.

`POST /api/v1/tenants/{tenantId}/federation:exchange` does everything that
`authenticate` does (verification of the upstream token against the provider's
JWKS, linking, group projection, a snapshot of the authentication context) and
immediately issues a short-lived token for a single audience:
`{identityProvider, token, audience, scopes}` →
`{accessToken, tokenType, expiresIn, audience, scope, sessionId, principalId,
identityProvider, groups, authenticationContext}`.

Differences from the PAT exchange:

- web login has no scope ceiling of its own: the ceiling is the audience
  allowlist, the requested scopes must be within it, and an empty list means the
  whole allowlist; a foreign audience — `403 audience_not_allowed`, a foreign
  scope — `403 scope_not_allowed`;
- `credential_id` in the token is the id of the external identity: disabling the
  identity closes the next exchange, and the resource service receives a stable
  key for its revocation cache;
- issuance is open only to Principals of kind `human`
  (`422 human_principal_required` for the others): service accounts and
  workloads stay on client credentials.

The token has the same shape as after the PAT exchange (`principal_type`,
`scope_ceiling`, `session_id`, `auth_time`, `acr`), so the resource service sees
no difference. A rejection on the upstream token answers with the same codes as
`authenticate`; in the audit the route writes `federation.exchange`, including
rejections by audience and scope.

Out of this slice: Entitlement Service, product licensing and service-local
domain RBAC.

## SCIM 2.0 provisioning

The Identity Provisioning Adapter accepts inbound SCIM 2.0 from an HR system or
IGA and projects it onto Principals, external identities and global groups.

- `Users` and `Groups` with `POST`, `GET`, `PUT`, `PATCH`, `DELETE`, filtering
  and paginated listing; `ServiceProviderConfig`, `ResourceTypes` and `Schemas`
  declare exactly what is actually supported;
- matching is done by the stable `externalId`: `userName` may change together
  with an employee's e-mail and is not an internal identity key;
- profile attributes (`name`, `emails`, phone numbers) are accepted and
  discarded — IAM is not a directory of personal data;
- the filter supports only `eq` and `and`; an unsupported operator is rejected
  as `invalidFilter` rather than silently widening the selection;
- `ETag` and `If-Match` guard against a race between two reconciliation passes;
  a repeated `add`/`remove` of a membership is idempotent and does not change the
  resource version;
- errors are returned as an `urn:ietf:params:scim:api:messages:2.0:Error`
  document.

The SCIM client presents an audience-bound access token of its confidential
service identity (`IAM_SCIM_AUDIENCE`, scope `IAM_SCIM_SCOPE`). A human
credential is not accepted on `/scim/v2`: provisioning manages someone else's
lifecycle and is not a way to log in. The source is determined by the service
identity from the token, so the client cannot declare a foreign tenant.

### One authoritative source per population

A population is an upstream identity provider. The `(tenant, provider)` pair is
unique, so SCIM and LDAP cannot write to the same population at the same time,
and for a provider with the `read_only` profile (its lifecycle is driven by the
directory) a SCIM source is not registered at all.

Provisioning creates an identity before the first login, when a real OIDC `sub`
does not exist yet. Until it does, `subject` holds a collision-free placeholder,
and on the first federation login the record is found by the stable external ID
and `subject` is replaced with the real one. No second Principal appears in the
process.

### Lifecycle and deprovisioning

`active: false` and `DELETE` disable the Principal and immediately revoke all of
its Platform Access Tokens — urgent revocation does not wait for the next
synchronization cycle. Deletion removes only the mappings that this source
produced: local memberships and identities of other sources remain untouched.
The membership of provisioned and federated groups is set by the upstream, so
the local API does not write to them.

Provisioning does not grant Product Entitlement or service-local grants: access
to a resource still requires separate decisions of entitlement-service and the
product's domain policy.

### Keycloak driver and source staleness

Writing to the upstream is configured on the source: `off` leaves only the IAM
projection, `scim` uses Keycloak's native SCIM API, `admin` — the stable Admin
API, `auto` tries SCIM and falls back to the Admin API if the endpoint is not
deployed or is temporarily unavailable. Unavailability of both paths closes
writing entirely (`502`): a divergence between the IAM projection and the
directory is more dangerous than a refusal.

The moment of the last synchronization is stored on the source.
`GET /api/v1/tenants/{tenantId}/provisioning-sources` shows the `stale` flag,
and the first detection publishes the `provisioning_source.stale` event — once
per episode, not on every read.

## Platform Access Token

A Principal-bound credential for Codex, Claude Code and other local plugins. It
is presented **only** to IAM and exchanged for a short-lived token of a single
audience — a single bearer for all services is forbidden.

- format `iam_pat_<public-prefix>_<secret>`; the server stores the lookup prefix
  and the SHA-256 of the full token, the full secret is shown exactly once;
- the holder may be a Principal of kind `human` or `agent`; service accounts and
  workloads stay on client credentials;
- issuance to a human requires confirmed human authentication: freshness is
  computed from the server-side `recorded_at`, so an old login cannot be passed
  off as a new one;
- the record contains name, audiences, scope ceiling, a snapshot of the
  authentication context, expiry, last-used, revocation and the predecessor on
  rotation;
- `Idempotency-Key` is mandatory on issuance and rotation: a retry after an
  ambiguous response returns the same record with `token: null` and does not
  create a second credential;
- rotation changes only the secret — it neither extends the window nor widens
  the authority; the predecessor is revoked in the same transaction;
- disabling a Principal revokes all of its credentials, and the exchange
  additionally re-checks the tenant, membership and Principal status on every
  request;
- any defect of the presented token yields the same `invalid_token`; the exact
  reason goes only to the audit, so that the endpoint is not an oracle.

An autonomous agent takes work from the queue itself and does not live inside
someone else's Run, so its credential is its own rather than borrowed from an
operator: otherwise the human's work and the agent's work would stop being
distinguishable in the audit. The agent has no human login, and no fresh
authentication context is required of it — nor can it pass itself off as a
human: the snapshot in the record says `agent_bootstrap`, the issued access
token has neither `auth_time` nor `acr`, and `principal_type` equals `agent`.

Effective scopes are the intersection of the requested ones, the token ceiling
and the audience allowlist. The ceiling only narrows authority: a scope absent
from the audience allowlist will not appear in the token even if it is written
in the ceiling.

### Compatibility window for the Control Plane API key

Until the cutover, the existing `cp_<prefix>_<secret>` key remains a working
credential. Both services use the same hash function, so only the
`(keyPrefix, keyHash)` pair is migrated into IAM — the plaintext key does not
cross the service boundary and does not appear in IAM at any step. An imported
record must have a bounded lifetime and cannot be issued indefinitely.

## Local harness login: `iam auth`

`iam_client` is the reference client for Codex, Claude Code and any other local
plugin. It is installed next to the harness, uses the same public HTTP contracts
as all other clients, and has no access to the IAM database.

```bash
iam auth login                       # hidden prompt; or `--stdin`
iam auth status                      # who is logged in, with what and until when
iam auth session --harness codex     # token exchange and Harness Session
iam auth logout --revoke             # local logout and revocation in IAM
```

The secret never passes through argv under any circumstances: the token is read
via a hidden prompt or from stdin, and an attempt to pass it as an argument is
rejected before the command is parsed — an argument is visible in the shell
history and in the process table, and a single appearance of it is enough to
consider the credential compromised.

### Repository binding

`.iam/binding.json` is committed and contains only non-secret metadata:

```json
{
  "iamUrl": "https://iam.example",
  "tenantId": "0f3f…",
  "audience": "control-plane",
  "controlPlaneUrl": "https://control-plane.example",
  "scopes": ["read"]
}
```

The file is checked for signs of a credential — a suspicious field name or a
value with the `iam_pat_`/`cp_` prefix rejects the binding as a whole. An
unbound working directory gets a refusal, not the credential of a neighbouring
project.

### Where the secret lives

1. an explicitly declared CI/runtime environment: `IAM_CREDENTIAL_MODE=environment`
   plus `IAM_PLATFORM_ACCESS_TOKEN`;
2. the OS credential store (macOS Keychain via `security`, the secret is passed
   only via stdin);
3. the file `$XDG_CONFIG_HOME/iam/credentials.json` with `0600` permissions as a
   fallback.

An environment variable without a declared mode is an error, not a silent
choice of source: an inherited variable must not quietly substitute the
developer's credential. The file is created with `0600` right away, and wider
permissions found on read are treated as an incident and close the login.

### Harness Session

`iam auth session` exchanges the PAT for a short-lived token of the
`control-plane` audience and opens a session in Control Plane itself. Codex and
Claude Code present the same Platform Access Token of the same Principal, but
each opens its own session with its own `harness_type`. The client does not
declare `control_level`: Control Plane derives `human_operated` from the kind of
Principal confirmed by the IAM token.

`logout` without the flag removes only the local copy — the same token could
have been saved on another machine. `--revoke` revokes it in IAM immediately:
the exchange stops working right away, not after the next synchronization cycle.

## A channel as a login method (Telegram)

A human can confirm a decision by replying in a messenger without opening the
web console. The channel is an external identity provider enabled **per
tenant**: `PUT /api/v1/tenants/{tenantId}/channel-providers/telegram` with
`{"status": "active"|"disabled"}` (bootstrap). While there is no record or it is
`disabled`, every step below is closed; the links themselves survive disabling.

Three steps and three presenters, all with an IAM access token for the audience
`IAM_CHANNEL_AUDIENCE` (default `iam`):

1. **Link code.** A human with their own token (`principal_type=human`,
   `auth_time` no older than `IAM_CHANNEL_LINK_MAX_AUTHENTICATION_AGE_SECONDS`,
   300 s) calls `POST .../channel-link-intents` `{"channel": "telegram"}` and
   receives a one-time code valid for 10 minutes (`channel_link_intents`: code
   SHA-256, Principal, expiry, used-at). The code is shown once. An agent token
   and a token issued by the channel itself (`acr=channel:*`) are rejected: only
   a full login may open a new login method.
2. **Confirmation.** The channel adapter, a service account with the scope
   `iam:channel-links`, brings the code the human sent to the bot and the
   account id: `POST .../channel-links:confirm`
   `{"channel", "code", "externalSubject"}`. This creates an `ExternalIdentity`
   with `source=channel` and issuer `iam:channel:telegram:{tenantId}`; the tenant
   in the issuer keeps links of different tenants independent. Unknown, foreign
   (another tenant), expired and used codes all answer `400 invalid_link_code`;
   the exact reason goes to audit only.
3. **Assertion exchange.** When the human replies to a notification, the adapter
   calls `POST .../channel-assertions:exchange`
   `{"channel", "externalSubject", "purposeRef"}` and receives a single-decision
   token:

   ```text
   aud = IAM_CHANNEL_ASSERTION_AUDIENCE (control-plane)
   scope = scope_ceiling = [IAM_CHANNEL_ASSERTION_SCOPE] (control-plane:decide)
   principal_type = human, acr = channel:telegram, amr = [channel:telegram]
   purpose_ref = purposeRef, credential_id = link id
   exp - iat = IAM_CHANNEL_ASSERTION_TTL_SECONDS (60)
   ```

   Audience and scope come from configuration, not from the request; the
   audience must be registered in the tenant and allow that scope. No
   authentication context snapshot is written: the channel does not unlock
   Platform Access Token issuance.

Refusals: `403 channel_provider_disabled`, `404 channel_account_not_linked` (no
link, or it was revoked), `403 principal_not_active`,
`422 human_principal_required` (the link points to an agent),
`403 audience_not_allowed`/`scope_not_allowed`, `409 channel_account_linked` (the
account is linked to another human), `409 channel_already_linked` (the human
already has a link for this channel), `403 service_account_required`,
`403 scope_not_granted`, `403 tenant_mismatch`, `401 invalid_token` (including a
revoked adapter service account, immediately rather than when its token
expires).

**Revocation.** A human lists their links with `GET .../channel-links` and
revokes one with `POST .../channel-links/{linkId}:revoke`; someone else's link
is indistinguishable from a missing one. The next exchange is closed, an already
issued token lives at most a minute, and the `channel_link.revoked` event
carries `credentialId` for revocation caches. Re-linking the same account
revives the previous record.

**Rate limits** are counted in the database (they survive restarts and are
shared by replicas); a refusal is `429 rate_limited` with `Retry-After`: codes
per Principal (`IAM_CHANNEL_LINK_INTENT_LIMIT`, 5 per 600 s), confirmation
failures per adapter (`IAM_CHANNEL_CONFIRM_FAILURE_LIMIT`, 10 per 600 s),
exchanges per link and exchange failures per adapter
(`IAM_CHANNEL_ASSERTION_LIMIT`, 10 per 60 s).

**Journal.** Outbox: `channel_provider.updated`, `channel_link_intent.created`,
`channel_link.confirmed`, `channel_link.revoked`. Audit records every decision
(`channel_providers.update`, `channel_link_intents.create`,
`channel_links.confirm`, `channel_links.revoke`, `channel_assertions.exchange`,
`channel_links.authenticate`) with the actor, the Principal and `purpose_ref`,
but without the code or the channel account id.

## Quick start

Create a local signing key that does not get into Git:

```bash
mkdir -p .secrets
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out .secrets/iam-signing.pem
```

Start PostgreSQL and the API:

```bash
docker compose up --build
```

The API is available at `http://localhost:8010`, health check — `/healthz`,
JWKS — `/.well-known/jwks.json`. The default bootstrap token value is intended
only for local development and must be replaced in any shared environment.

## Local development

```bash
uv sync
uv run pytest
uv run ruff check .
```

Migrations against the local PostgreSQL from Compose:

```bash
IAM_DATABASE_URL=postgresql+psycopg://iam:iam@localhost:5435/iam \
  uv run alembic upgrade head
```

For a production-like run `IAM_CREATE_SCHEMA_ON_STARTUP` stays `false`: only
Alembic changes the schema.

The regular test run is self-contained and uses a local fake OIDC issuer.
Verification against a live Keycloak with LDAP is described in
[deploy/keycloak/README.md](deploy/keycloak/README.md) and is run separately
via `pytest -m integration`.

## Main HTTP contracts

Bootstrap management API:

- `POST /api/v1/tenants`;
- `POST /api/v1/tenants/{tenantId}/principals`;
- `GET /api/v1/tenants/{tenantId}/principals/{principalId}`;
- `POST /api/v1/tenants/{tenantId}/principals/{principalId}/external-identities`;
- `POST /api/v1/tenants/{tenantId}/identity-providers`;
- `POST /api/v1/tenants/{tenantId}/groups`;
- `POST /api/v1/tenants/{tenantId}/groups/{groupId}/members`;
- `POST /api/v1/tenants/{tenantId}/audiences`;
- `POST /api/v1/tenants/{tenantId}/service-accounts`;
- `POST /api/v1/tenants/{tenantId}/service-accounts/{clientId}:revoke`;
- `POST /api/v1/tenants/{tenantId}/principals/{principalId}:disable`;
- `POST /api/v1/tenants/{tenantId}/principals/{principalId}/authentication-contexts`;
- `POST /api/v1/tenants/{tenantId}/principals/{principalId}/platform-access-tokens`;
- `GET /api/v1/tenants/{tenantId}/platform-access-tokens`;
- `POST /api/v1/tenants/{tenantId}/platform-access-tokens/{credentialId}:rotate`;
- `POST /api/v1/tenants/{tenantId}/platform-access-tokens/{credentialId}:revoke`;
- `POST /api/v1/tenants/{tenantId}/legacy-credentials:import`;
- `POST /api/v1/tenants/{tenantId}/provisioning-sources`;
- `GET /api/v1/tenants/{tenantId}/provisioning-sources`;
- `PUT /api/v1/tenants/{tenantId}/channel-providers/{channel}`;
- `GET /api/v1/tenants/{tenantId}/channel-providers`;
- `GET /api/v1/events`.

SCIM 2.0 API (confidential service identity):

- `GET|POST /scim/v2/Users` and `GET|PUT|PATCH|DELETE /scim/v2/Users/{id}`;
- `GET|POST /scim/v2/Groups` and `GET|PUT|PATCH|DELETE /scim/v2/Groups/{id}`;
- `GET /scim/v2/ServiceProviderConfig`, `/scim/v2/ResourceTypes`,
  `/scim/v2/Schemas`.

Credential and federation API:

- `POST /api/v1/platform-access-tokens:exchange`;
- `POST /api/v1/platform-access-tokens:introspect`;
- `POST /api/v1/platform-access-tokens:revoke-self`;
- `POST /api/v1/tokens/exchange`;
- `POST /api/v1/tenants/{tenantId}/federation:authenticate`;
- `POST /api/v1/tenants/{tenantId}/federation:exchange`;
- `GET /.well-known/jwks.json`.

Channel as a login method (IAM token of the human or of the channel adapter):

- `POST /api/v1/tenants/{tenantId}/channel-link-intents`;
- `GET /api/v1/tenants/{tenantId}/channel-links`;
- `POST /api/v1/tenants/{tenantId}/channel-links/{linkId}:revoke`;
- `POST /api/v1/tenants/{tenantId}/channel-links:confirm`;
- `POST /api/v1/tenants/{tenantId}/channel-assertions:exchange`.

`platform-access-tokens:exchange` does not accept `tenantId` and `principalId`
from the client: they are taken from the record of the presented token. An
issued access token is not a credential and is rejected on this endpoint.

`introspect` and `revoke-self` present the same PAT in the request body and pass
the same verification as the exchange. `introspect` returns only identity, the
authority boundaries and the expiry — neither the secret nor its hash.
`revoke-self` lets the owner of the secret revoke their own token without
bootstrap privileges; this operation cannot widen authority, and a repeated call
with a revoked token answers with the same `invalid_token` and does not confirm
that the record exists.

`federation:authenticate` accepts only an upstream token: the `username` and
`password` fields are forbidden by the contract, the directory password is
verified exclusively by the IdP. While an upstream IdP is registered with the
`read_only` profile, manual linking of an external identity for its issuer is
closed, and federated groups are not edited by the local API — the membership
is set by the upstream.

The bootstrap header is a temporary administration boundary of the first slice.
It must not be proxied to external clients or considered a replacement for a
scoped IAM admin role.

## Token contract

The access token carries minimal claims:

```text
iss, sub, tenant_id, aud
principal_type, credential_id
scope, iat, nbf, exp, jti
```

A token issued in exchange for a Platform Access Token or via
`federation:exchange` additionally carries `scope_ceiling`, `session_id`,
`auth_time` and `acr`. A token issued for a channel assertion carries the same
plus `amr` and `purpose_ref` and lives 60 seconds (see "A channel as a login
method").

A resource service must verify the RS256 signature, the exact issuer and
audience, the time claims and its local revocation policy. `scope` is a ceiling
and does not create a service-local permission. The token contains no Product,
Plan, License, Workspace, Project, Task or Memory namespace.

## Outbox and audit

The domain mutation, the outbox event and the audit event are written in a
single transaction. The event payload contains only stable identifiers and
bounded metadata. The service secret, the Argon2 hash, the access token and the
external `subject` are not published to the outbox.

Background outbox delivery and an external broker belong to the next vertical
slice. Until then, `GET /api/v1/events` provides an ordered journal for contract
validation.

## Entitlement boundary

IAM Service does not know whether Control Plane or Memory Service is licensed.
After verifying the IAM token, the resource service separately obtains a
decision from `entitlement-service` and then applies its own domain policy. This
makes it possible to grant one identity different product licences without
changing the Principal or the credential lifecycle.
