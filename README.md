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

Не входят в этот срез: Entitlement Service, product licensing и service-local
domain RBAC.

## SCIM 2.0 provisioning

Identity Provisioning Adapter принимает входящий SCIM 2.0 от кадровой системы
или IGA и проецирует его на Principal, external identity и глобальные группы.

- `Users` и `Groups` с `POST`, `GET`, `PUT`, `PATCH`, `DELETE`, фильтрацией и
  постраничной выдачей; `ServiceProviderConfig`, `ResourceTypes` и `Schemas`
  объявляют ровно то, что действительно поддерживается;
- сопоставление ведётся по стабильному `externalId`: `userName` может меняться
  вместе с почтой сотрудника и внутренним identity key не является;
- профильные атрибуты (`name`, `emails`, телефоны) принимаются и отбрасываются —
  IAM не является каталогом персональных данных;
- фильтр поддерживает только `eq` и `and`; неподдерживаемый оператор отклоняется
  как `invalidFilter`, а не молча расширяет выборку;
- `ETag` и `If-Match` защищают от гонки двух reconciliation-проходов; повтор
  `add`/`remove` членства идемпотентен и не меняет версию ресурса;
- ошибки возвращаются документом `urn:ietf:params:scim:api:messages:2.0:Error`.

SCIM-клиент предъявляет audience-bound access token своей confidential service
identity (`IAM_SCIM_AUDIENCE`, scope `IAM_SCIM_SCOPE`). Человеческий credential
на `/scim/v2` не принимается: provisioning управляет чужим lifecycle и способом
входа не является. Source определяется по service identity из токена, поэтому
клиент не может объявить чужой tenant.

### Один authoritative source на population

Population — это upstream identity provider. Пара `(tenant, provider)`
уникальна, поэтому SCIM и LDAP не могут писать в одну population одновременно, а
для провайдера с профилем `read_only` (его lifecycle ведёт каталог)
SCIM-источник не регистрируется вовсе.

Provisioning заводит identity до первого входа, когда реального OIDC `sub` ещё
нет. Пока его нет, `subject` держит неколлизионный placeholder, а при первом
federation-входе запись находится по стабильному external ID и `subject`
заменяется настоящим. Второй Principal при этом не появляется.

### Lifecycle и деинициализация

`active: false` и `DELETE` отключают Principal и немедленно отзывают все его
Platform Access Token — срочный отзыв не ждёт следующего цикла синхронизации.
Удаление снимает только те mappings, которые породил этот source: локальные
членства и identity других источников остаются нетронутыми. Состав provisioned
и federated групп задаёт upstream, поэтому локальный API в них не пишет.

Provisioning не выдаёт Product Entitlement и service-local grants: доступ к
ресурсу по-прежнему требует отдельных решений entitlement-service и domain
policy продукта.

### Драйвер Keycloak и устаревание источника

Запись в upstream настраивается на источнике: `off` оставляет только проекцию
IAM, `scim` использует native SCIM API Keycloak, `admin` — стабильный Admin API,
`auto` пробует SCIM и падает обратно на Admin API, если endpoint не развёрнут
или временно недоступен. Недоступность обеих дорог закрывает запись целиком
(`502`): расхождение проекции IAM с каталогом опаснее отказа.

Момент последней синхронизации хранится на источнике.
`GET /api/v1/tenants/{tenantId}/provisioning-sources` показывает признак
`stale`, а первое обнаружение публикует событие `provisioning_source.stale` —
один раз на эпизод, а не на каждое чтение.

## Platform Access Token

Principal-bound credential для Codex, Claude Code и других локальных плагинов.
Предъявляется **только** IAM и обменивается на короткоживущий token одного
audience — единый bearer для всех сервисов запрещён.

- формат `iam_pat_<public-prefix>_<secret>`; сервер хранит lookup prefix и
  SHA-256 полного токена, полный секрет показывается ровно один раз;
- держателем может быть Principal вида `human` или `agent`; service account и
  workload остаются на client credentials;
- выпуск человеку требует подтверждённого human authentication: свежесть
  считается по серверному `recorded_at`, поэтому старый вход нельзя выдать за
  новый;
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

Автономный агент берёт работу из очереди сам и внутри чужого Run не живёт,
поэтому credential у него собственный, а не одолженный у оператора: иначе в
audit работа человека и работа агента перестали бы различаться. Человеческого
входа у агента нет, свежий authentication context с него не требуется — и выдать
себя за человека он не может: снимок в записи говорит `agent_bootstrap`, а в
выданном access token нет ни `auth_time`, ни `acr`, и `principal_type` равен
`agent`.

Эффективные scopes — пересечение запрошенных, ceiling токена и allowlist
audience. Ceiling только сужает authority: scope, отсутствующий в allowlist
audience, не появится в token, даже если он записан в ceiling.

### Compatibility window для Control Plane API key

До cutover существующий ключ `cp_<prefix>_<secret>` остаётся рабочим
credential. Хэш-функция у обоих сервисов одна, поэтому в IAM переносится
только пара `(keyPrefix, keyHash)` — открытый ключ не пересекает границу
сервисов и не появляется в IAM ни на одном шаге. Импортированная запись
обязана иметь ограниченный срок и не может быть выпущена бессрочно.

## Вход локального harness: `iam auth`

`iam_client` — reference-клиент для Codex, Claude Code и любого другого
локального плагина. Он ставится рядом с harness, ходит по тем же публичным
HTTP-контрактам, что и остальные клиенты, и не имеет доступа к базе IAM.

```bash
iam auth login                       # скрытый prompt; или `--stdin`
iam auth status                      # кто вошёл, чем и до какого момента
iam auth session --harness codex     # обмен токена и Harness Session
iam auth logout --revoke             # локальный выход и отзыв в IAM
```

Секрет не проходит через argv ни при каких условиях: токен читается скрытым
prompt или из stdin, а попытка передать его аргументом отклоняется до разбора
команды — аргумент виден в истории оболочки и в таблице процессов, и одного
его появления достаточно, чтобы считать credential скомпрометированным.

### Привязка репозитория

`.iam/binding.json` коммитится и содержит только несекретные metadata:

```json
{
  "iamUrl": "https://iam.example",
  "tenantId": "0f3f…",
  "audience": "control-plane",
  "controlPlaneUrl": "https://control-plane.example",
  "scopes": ["read"]
}
```

Файл проверяется на признаки credential — подозрительное имя поля или значение
с префиксом `iam_pat_`/`cp_` отклоняет binding целиком. Непривязанный рабочий
каталог получает отказ, а не credential соседнего проекта.

### Где живёт секрет

1. явно объявленный CI/runtime environment: `IAM_CREDENTIAL_MODE=environment`
   плюс `IAM_PLATFORM_ACCESS_TOKEN`;
2. OS credential store (macOS Keychain через `security`, секрет передаётся
   только stdin);
3. файл `$XDG_CONFIG_HOME/iam/credentials.json` с правами `0600` как fallback.

Переменная окружения без объявленного режима — ошибка, а не тихий выбор
источника: унаследованная переменная не должна незаметно подменять credential
разработчика. Файл создаётся сразу с `0600`, а расширенные права при чтении
считаются инцидентом и закрывают вход.

### Harness Session

`iam auth session` меняет PAT на короткоживущий token audience
`control-plane` и открывает session уже в Control Plane. Codex и Claude Code
предъявляют один и тот же Platform Access Token одного Principal, но каждый
открывает собственную session со своим `harness_type`. `control_level` клиент
не объявляет: Control Plane выводит `human_operated` из вида Principal,
подтверждённого IAM-токеном.

`logout` без флага удаляет только локальную копию — тот же токен мог быть
сохранён на другой машине. `--revoke` отзывает его в IAM немедленно: обмен
перестаёт работать сразу, а не после следующего цикла синхронизации.

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
- `POST /api/v1/tenants/{tenantId}/provisioning-sources`;
- `GET /api/v1/tenants/{tenantId}/provisioning-sources`;
- `GET /api/v1/events`.

SCIM 2.0 API (confidential service identity):

- `GET|POST /scim/v2/Users` и `GET|PUT|PATCH|DELETE /scim/v2/Users/{id}`;
- `GET|POST /scim/v2/Groups` и `GET|PUT|PATCH|DELETE /scim/v2/Groups/{id}`;
- `GET /scim/v2/ServiceProviderConfig`, `/scim/v2/ResourceTypes`,
  `/scim/v2/Schemas`.

Credential и federation API:

- `POST /api/v1/platform-access-tokens:exchange`;
- `POST /api/v1/platform-access-tokens:introspect`;
- `POST /api/v1/platform-access-tokens:revoke-self`;
- `POST /api/v1/tokens/exchange`;
- `POST /api/v1/tenants/{tenantId}/federation:authenticate`;
- `GET /.well-known/jwks.json`.

`platform-access-tokens:exchange` не принимает `tenantId` и `principalId` от
клиента: они берутся из записи предъявленного токена. Выданный access token не
является credential и на этом endpoint отклоняется.

`introspect` и `revoke-self` предъявляют тот же PAT телом запроса и проходят
ту же проверку, что и обмен. `introspect` возвращает только identity, границы
authority и срок — ни секрета, ни его hash. `revoke-self` даёт владельцу
секрета отозвать свой токен без bootstrap-полномочий; расширить authority эта
операция не может, а повторный вызов отозванным токеном отвечает тем же
`invalid_token` и существование записи не подтверждает.

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
