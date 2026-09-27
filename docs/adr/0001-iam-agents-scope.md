# ADR-0001 (IAM): scope `iam:agents` — агенты, которыми владеет service account

*English title: IAM scope `iam:agents` — agents owned by a service account.*

- Статус: принято (фича declarative-agents, задача D003; дизайн TASK-000584,
  ворота одобрены владельцем 2026-09-27).
- Требования: FR-004, FR-008; конституция, ст. VI.
- Границы: верхнеуровневые ADR-0012 (Platform Access Token) и ADR-0013 (IAM
  отделён от entitlement и доменной авторизации). Это решение их не меняет:
  формат PAT, обмен и claims access token остаются прежними.

## Контекст

Декларативные агенты поднимаются платформой по желаемому состоянию: правка
YAML — и контроллер сам заводит исполнителя и выдаёт ему credential. До сих
пор Principal вида `agent` и его PAT заводились только bootstrap-операциями
(`X-IAM-Bootstrap-Token`). Отдавать bootstrap-токен контроллеру нельзя: это
administration boundary всего IAM, а контроллеру нужно ровно одно — управлять
своими агентами.

## Решение

1. **Scope `iam:agents`** audience самого IAM (`IAM_AGENTS_AUDIENCE`, по
   умолчанию `iam`; `IAM_AGENTS_SCOPE`). Держать его может только confidential
   service account: предъявитель — access token IAM с `principal_type =
   service_account`, этим scope и tenant, совпадающим с путём. Service account
   заводит bootstrap один раз; дальше контроллер работает без bootstrap.
   Отзыв service account, отключение его Principal или membership закрывают
   путь сразу — по записи, а не по истечению token.
2. **Владелец Principal.** Колонка `principals.owner_principal_id` (миграция
   `0006_agent_owner`, nullable, FK на `principals`). `POST
   /api/v1/tenants/{t}/agents` заводит Principal вида `agent`, владелец —
   Principal вызывающего service account. У principal, заведённых
   bootstrap-операцией, владельца нет.
3. **PAT агента.** `POST …/agents/{id}/platform-access-tokens` с обязательными
   `Idempotency-Key` и `expiresInSeconds` (не больше
   `IAM_AGENT_PAT_MAX_TTL_SECONDS`, 7 суток — короче человеческого PAT: его
   перевыпускает контроллер, а не человек). Отзыв — `POST
   …/agents/{id}/platform-access-tokens/{credentialId}:revoke`, тем же путём
   отзыва, что у bootstrap (событие `credential.revoked`, audit).
4. **Только свои агенты.** Чужой агент и агент без владельца — `403
   agent_not_owned`; Principal другого вида (human, service account, workload)
   — `422 agent_principal_required`. Оба отказа пишутся в audit с точной
   причиной. Replay по `Idempotency-Key` проверяется после владения, а ключ,
   уже занятый credential другого агента, — `409 idempotency_key_reused`.
5. **Authority агента не шире владельца.** Audiences PAT — подмножество
   audiences service account, потолок scope — подмножество его потолка и
   allowlist audience; `iam:agents` не делегируется никогда. Иначе контроллер
   с узким потолком выпускал бы агентам authority, которой не держит сам.
6. **Честное происхождение.** Снимок в записи PAT — `{"source": "agent_owner",
   "ownerPrincipalId", "serviceAccountId", "recordedAt"}`; в access token
   агента, как и прежде, нет ни `auth_time`, ни `acr`, `principal_type =
   agent`. Actor в audit — Principal владельца.

## Последствия

- Контракт токена не меняется: `platform-auth-sdk` видит тот же обмен PAT и те
  же claims, contract-тест не требуется сверх существующих.
- `GET …/principals/{id}` дополнительно отдаёт `owner_principal_id`; событие
  `principal.created` для агента владельца несёт `ownerPrincipalId`.
- Отключение service account-владельца не отключает его агентов и не отзывает
  их PAT автоматически: это решение контроллера (или bootstrap через
  `:disable`). Каскад — кандидат на отдельное решение.
- Список PAT агента и ротация владельцу пока не нужны: контроллер получает id
  credential при выпуске и перевыпускает по сроку. Создание агента не
  идемпотентно — повтор после неоднозначного ответа заведёт второго агента.

## Отвергнутые варианты

- **Bootstrap-токен контроллеру** — нарушает ст. VI: администрирование всего
  IAM вместо своих агентов.
- **PAT самому service account** — PAT остаётся credential человека или агента;
  service account живёт на client credentials, и агент в audit должен быть
  отдельной identity, а не контроллером.
- **Владение через группу или entitlement** — владение — факт identity, а не
  доменная авторизация (ADR-0013); группа добавила бы второй источник правды.
