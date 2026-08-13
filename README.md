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

## Identity federation

- registry upstream identity providers: issuer, ожидаемый audience, claim names,
  allowlist групп и lifecycle profile;
- OIDC discovery и JWKS с кэшем, bounded stale window и fail closed после него;
- строгая проверка upstream token: подпись, точный issuer, точный audience,
  временные claims; симметричные алгоритмы и `none` отклоняются;
- linking по `issuer + subject` со сверкой стабильного external ID
  (для LDAP — `entryUUID`), чтобы одна upstream identity не получила двух
  Principals;
- authentication context `acr`/`amr`/`auth_time` и step-up: недостаточный
  контекст закрывает вход, а не понижает требования;
- проекция upstream-групп в IAM Groups строго по allowlist mappings;
- reference deployment Keycloak с LDAP User Federation в `deploy/keycloak`.

Federation подтверждает identity и групповую проекцию. Она не выдаёт Product
Entitlement, audience credential или service-local role: доступ к ресурсу
по-прежнему требует отдельных решений entitlement и domain policy.

Не входят в этот срез: SCIM adapter, Entitlement Service, product licensing и
service-local domain RBAC.

## Platform Access Token

Principal-bound credential человека для Codex, Claude Code и других локальных
плагинов. Предъявляется **только** IAM и обменивается на короткоживущий token
одного audience — единый bearer для всех сервисов запрещён.

- формат `iam_pat_<public-prefix>_<secret>`; сервер хранит lookup prefix и
  SHA-256 полного токена, полный секрет показывается ровно один раз;
- выпуск требует подтверждённого human authentication: свежесть считается по
  серверному `recorded_at`, поэтому старый вход нельзя выдать за новый;
- запись содержит name, audiences, scope ceiling, снимок authentication
  context, expiry, last-used, revocation и предшественника при ротации;
- `Idempotency-Key` обязателен при выпуске и ротации: повтор при ambiguous
  response возвращает ту же запись с `token: null` и не создаёт второй
  credential;
- ротация меняет только секрет — она не продлевает окно и не расширяет
  authority; предшественник отзывается в той же транзакции;
- отключение Principal отзывает все его credentials, а обмен дополнительно
  перепроверяет tenant, membership и статус Principal на каждом запросе;
- любой дефект предъявленного токена даёт один и тот же `invalid_token`;
  точная причина уходит только в audit, чтобы endpoint не был оракулом.

Эффективные scopes — пересечение запрошенных, ceiling токена и allowlist
audience. Ceiling только сужает authority: scope, отсутствующий в allowlist
audience, не появится в token, даже если он записан в ceiling.

### Compatibility window для Control Plane API key

До cutover существующий ключ `cp_<prefix>_<secret>` остаётся рабочим
credential. Хэш-функция у обоих сервисов одна, поэтому в IAM переносится
только пара `(keyPrefix, keyHash)` — открытый ключ не пересекает границу
сервисов и не появляется в IAM ни на одном шаге. Импортированная запись
обязана иметь ограниченный срок и не может быть выпущена бессрочно.

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

Обычный прогон тестов автономен и использует локальный фиктивный OIDC issuer.
Проверка против живого Keycloak с LDAP описана в
[deploy/keycloak/README.md](deploy/keycloak/README.md) и запускается отдельно
через `pytest -m integration`.

## Основные HTTP-контракты

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
- `GET /api/v1/events`.

Credential и federation API:

- `POST /api/v1/platform-access-tokens:exchange`;
- `POST /api/v1/tokens/exchange`;
- `POST /api/v1/tenants/{tenantId}/federation:authenticate`;
- `GET /.well-known/jwks.json`.

`platform-access-tokens:exchange` не принимает `tenantId` и `principalId` от
клиента: они берутся из записи предъявленного токена. Выданный access token не
является credential и на этом endpoint отклоняется.

`federation:authenticate` принимает только upstream token: поля `username` и
`password` контрактом запрещены, пароль каталога проверяет исключительно IdP.
Пока upstream IdP зарегистрирован с профилем `read_only`, ручная привязка
external identity для его issuer закрыта, а federated группы не редактируются
локальным API — состав задаёт upstream.

Bootstrap header является временной administration boundary первого среза. Его
нельзя проксировать внешним клиентам или считать заменой scoped IAM admin role.

## Token contract

Access token содержит минимальные claims:

```text
iss, sub, tenant_id, aud
principal_type, credential_id
scope, iat, nbf, exp, jti
```

Token, выданный в обмен на Platform Access Token, дополнительно несёт
`scope_ceiling`, `session_id`, `auth_time` и `acr`.

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
