# ADR-0005 (IAM): изменение потолка service account с сохранением Principal

*English title: IAM service account ceiling update that keeps the Principal.*

- Статус: принято (фича integrations-connections, задача TASK-001046; найдено
  в I007, TASK-000994, 2026-09-30).
- Требования: конституция, ст. VI (узкий путь, журнал, тесты отказа).
- Дополняет: [ADR-0001](0001-iam-agents-scope.md) (владение агентами),
  [ADR-0003](0003-privileged-scopes.md), п. 5 (привилегированные scope service
  account — только явным решением bootstrap).
- Границы: верхнеуровневые ADR-0012 и ADR-0013. Формат access token и claims
  не меняются.

## Контекст

Audiences и потолок scope service account задавались только при создании.
Чтобы расширить потолок, `deploy/bootstrap.py` суперпроекта заводил новый
service account. Для fleet-controller это ломает агентов: их Principal
принадлежат Principal'у старого service account (ADR-0001, п. 2), и новый
получает `403 agent_not_owned` при перевыпуске их PAT. Runbook предлагал
ручной SQL `UPDATE principals SET owner_principal_id`.

Рассматривались два пути: изменять потолок существующего service account или
передавать владение агентами новому (`POST …/principals/{id}:transfer-ownership`).

## Решение

1. **`PATCH /api/v1/tenants/{t}/service-accounts/{clientId}`** — только
   bootstrap (`X-IAM-Bootstrap-Token`), как создание и отзыв. Тело
   `{"audiences"?, "scopeCeiling"?, "rotateSecret"?}`: пропущенное поле не
   меняется, список заменяется целиком. Ответ — `{"principalId", "clientId",
   "audiences", "scopeCeiling", "clientSecret"}`; `clientSecret` не `null`
   только при `rotateSecret: true`. Principal, client id и id credential
   сохраняются — агенты остаются агентами того же владельца.
2. **В пределах реестра audience.** Каждый audience — активный audience
   tenant'а (`422 unknown_audience`); каждый scope потолка разрешён хотя бы
   одним audience service account (`422 invalid_scope_ceiling`). Порядок для
   развёртывания: сначала `PATCH …/audiences/{key}`, потом потолок. Scope
   `iam:*` и привилегированные scope (ADR-0003) попадают в потолок только так
   же, как при создании, — решением bootstrap; `iam:people` client credentials
   по-прежнему не выдают (ADR-0002).
3. **Ротация секрета** — по желанию, в том же запросе. Старый секрет перестаёт
   работать с commit; уже выданные по нему access token живут до своего TTL
   (`IAM_TOKEN_TTL_SECONDS`). Утечку закрывает отзыв (`:revoke`), а не ротация.
4. **Сужение действует по записи.** Guard `iam:agents` (ADR-0001, п. 1)
   дополнительно сверяет потолок и audiences service account из базы: снятый
   `iam:agents` или audience IAM закрывают путь агентов сразу —
   `403 scope_not_granted`, audit `agents.authenticate` с `reason =
   scope_ceiling`. Выпуск PAT агенту и так сверяется с текущей записью
   (ADR-0001, п. 5).
5. **Журнал.** Изменение — событие `service_account.updated`
   (`serviceAccountId`, `principalId`, `audiences`, `scopeCeiling`) и audit
   `service_accounts.update` с разницей в `reason`
   (`audience:+memory-service,scope:+memory:read`). Ротация — событие
   `service_account.secret_rotated` и audit `service_accounts.rotate_secret`;
   секрет не попадает ни в событие, ни в audit. Повтор того же состояния без
   ротации ничего не пишет (идемпотентно, как `PATCH …/audiences/{key}`).
   Отказы валидации — `4xx` без записи, как у создания.

## Последствия

- `deploy/bootstrap.py` суперпроекта (отдельная правка): при изменении
  потолка вызывать `PATCH` существующего service account, а не заводить новый;
  ручной SQL из runbook убрать. Новый секрет нужен, только если его
  запросили.
- Уже выпущенные PAT агентов сохраняют потолок, с которым их выпустили, до
  истечения (не дольше `IAM_AGENT_PAT_MAX_TTL_SECONDS`): сужение потолка
  владельца их не отзывает. Контроллер, которому это важно, отзывает их сам.
- Уже выданные access token service account несут прежние scope до TTL; для
  маршрутов агентов это не так (п. 4), для чужих audience — как при отзыве
  членства (ADR-0003, п. 6).
- Контракт токена не меняется; `platform-auth-sdk` не затронут.

## Отвергнутые варианты

- **`POST …/principals/{id}:transfer-ownership`** — лечит последствие, а не
  причину: каждое изменение потолка по-прежнему плодит service account,
  старый нужно отзывать, а агенты на время между заведением нового и
  переносом остаются без владельца, способного их обслужить. Передача
  владения — отдельная authority (перенос агентов между контроллерами),
  которая сейчас не нужна.
- **Ротация секрета отдельной операцией** — возможна позже; сейчас секрет
  меняется тогда же, когда bootstrap переписывает конфигурацию контроллера,
  и одна операция не оставляет окна между изменением потолка и выдачей
  секрета.
- **Проверка потолка против реестра только при выдаче token** (как при
  создании) — ошибка развёртывания молча превращалась бы в `403` у сервиса
  много позже; при изменении потолка её дешевле поймать сразу.
