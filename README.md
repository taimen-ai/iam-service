# IAM Service

Product-neutral backend единой identity для независимо поставляемых и
лицензируемых resource services. IAM Service подтверждает Principal и Tenant,
выпускает короткоживущие audience-specific credentials и публикует identity
events. Он не хранит лицензии и не заменяет доменную авторизацию Control Plane,
Memory Service или другого продукта.

Канонические границы определены верхнеуровневым ADR-0013.

## Что реализовано в foundation

- Tenant и Tenant Membership;
- Principal типов `human`, `agent`, `service_account`, `workload`;
- external identity с глобально уникальной парой `issuer + subject`;
- tenant-scoped global Groups и memberships;
- tenant-scoped Audience registry и allowlist scopes;
- service account secret с Argon2 hash и one-time display;
- RS256 access token с точным audience, Tenant и scope ceiling;
- JWKS endpoint для локальной проверки resource services;
- отзыв service account и прекращение нового token exchange;
- append-only event journal через transactional outbox;
- отдельный audit без token/secret/subject payload;
- Alembic migration и Docker Compose с собственной PostgreSQL.

Не входят в этот срез: Platform Access Token человека, OIDC/SCIM adapters,
Entitlement Service, product licensing и service-local domain RBAC.

## Быстрый запуск

Создать локальный signing key, который не попадает в Git:

```bash
mkdir -p .secrets
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out .secrets/iam-signing.pem
```

Запустить PostgreSQL и API:

```bash
docker compose up --build
```

API доступен на `http://localhost:8010`, health check — `/healthz`, JWKS —
`/.well-known/jwks.json`. Значение bootstrap token по умолчанию предназначено
только для локальной разработки и должно быть заменено в любом общем окружении.

## Локальная разработка

```bash
uv sync
uv run pytest
uv run ruff check .
```

Миграции с локальной PostgreSQL из Compose:

```bash
IAM_DATABASE_URL=postgresql+psycopg://iam:iam@localhost:5435/iam \
  uv run alembic upgrade head
```

Для production-like запуска `IAM_CREATE_SCHEMA_ON_STARTUP` остаётся `false`:
schema изменяет только Alembic.

## Основные HTTP-контракты

Bootstrap management API:

- `POST /api/v1/tenants`;
- `POST /api/v1/tenants/{tenantId}/principals`;
- `GET /api/v1/tenants/{tenantId}/principals/{principalId}`;
- `POST /api/v1/tenants/{tenantId}/principals/{principalId}/external-identities`;
- `POST /api/v1/tenants/{tenantId}/groups`;
- `POST /api/v1/tenants/{tenantId}/groups/{groupId}/members`;
- `POST /api/v1/tenants/{tenantId}/audiences`;
- `POST /api/v1/tenants/{tenantId}/service-accounts`;
- `POST /api/v1/tenants/{tenantId}/service-accounts/{clientId}:revoke`;
- `GET /api/v1/events`.

Credential API:

- `POST /api/v1/tokens/exchange`;
- `GET /.well-known/jwks.json`.

Bootstrap header является временной administration boundary первого среза. Его
нельзя проксировать внешним клиентам или считать заменой scoped IAM admin role.

## Token contract

Access token содержит минимальные claims:

```text
iss, sub, tenant_id, aud
principal_type, credential_id
scope, iat, nbf, exp, jti
```

Resource service обязан проверять RS256 signature, точные issuer и audience,
временные claims и локальную revocation policy. `scope` является ceiling и не
создаёт service-local permission. Token не содержит Product, Plan, License,
Workspace, Project, Task или Memory namespace.

## Outbox и audit

Доменная mutation, outbox event и audit event записываются одной транзакцией.
Event payload содержит только стабильные identifiers и bounded metadata. Service
secret, Argon2 hash, access token и external `subject` в outbox не публикуются.

Фоновая доставка outbox и внешний broker находятся в следующем вертикальном
срезе. До него `GET /api/v1/events` предоставляет упорядоченный journal для
contract validation.

## Граница Entitlement

IAM Service не знает, лицензирован ли Control Plane или Memory Service. Resource
service после проверки IAM token отдельно получает decision от
`entitlement-service`, а затем применяет свою domain policy. Это позволяет
выдавать одной identity разные лицензии на продукты без изменения Principal или
credential lifecycle.
