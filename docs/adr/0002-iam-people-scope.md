# ADR-0002 (IAM): scope `iam:people` — управление людьми без bootstrap-токена

*English title: IAM scope `iam:people` — managing people without the bootstrap token.*

- Статус: принято (фича runtime-console, задача R003; план одобрен владельцем
  2026-09-29; дополнено по ревью владельца 2026-09-29 — гейт администратора,
  онбординг-привязка, защита от отключения себя и администраторов; по
  повторному ревью — онбординг только цели без какого-либо способа входа,
  блокировка цели, группа администраторов только от bootstrap; п. 3–4
  обобщены на все привилегированные scope в
  [ADR-0003](0003-privileged-scopes.md) — `iam:people` там частный случай;
  амендмент 2026-09-29, TASK-000908 — чтение external identities, п. 11;
  амендмент 2026-09-29, TASK-000907 — `:enable`, обратная операция к
  `:disable`, п. 12).
- Требования: FR-013, FR-004; конституция, ст. V, VI.
- Прецедент: [ADR-0001](0001-iam-agents-scope.md) (`iam:agents`).
- Границы: верхнеуровневые ADR-0012 (Platform Access Token) и ADR-0013 (IAM
  отделён от entitlement и доменной авторизации). Формат access token и его
  claims не меняются.

## Контекст

Консоль runtime добавляет человека одним потоком от имени вошедшего владельца
(сценарий 6 spec runtime-console): IAM principal → external identity → связка
в ядре. Отключает — тоже от его имени. До сих пор principals tenant'а заводил,
читал и отключал только bootstrap (`X-IAM-Bootstrap-Token`) — administration
boundary всего IAM, которую нельзя отдавать ни браузеру, ни BFF консоли.
Журнал должен называть человека, а не «bootstrap» (FR-004).

## Решение

1. **Scope `iam:people`** audience самого IAM (`IAM_PEOPLE_AUDIENCE`, по
   умолчанию `iam`; `IAM_PEOPLE_SCOPE`). Маршруты

   - `POST /api/v1/tenants/{t}/principals`,
   - `GET /api/v1/tenants/{t}/principals` (новый, список),
   - `GET /api/v1/tenants/{t}/principals/{p}`,
   - `POST …/principals/{p}/external-identities`,
   - `GET …/principals/{p}/external-identities` и
     `GET /api/v1/tenants/{t}/external-identities` (чтение, п. 11),
   - `POST …/principals/{p}:disable`,
   - `POST …/principals/{p}:enable` (п. 12)

   принимают, кроме bootstrap-токена, `Authorization: Bearer` с access token
   IAM этого audience. Предъявленный bootstrap-заголовок проверяется как прежде
   и не уступает место Bearer: неверный — `401 unauthorized`.
2. **Только человек и только из federation.** Предъявитель — token с
   `principal_type = human`, scope `iam:people` и tenant, совпадающим с путём;
   его `credential_id` — активная external identity этого человека, связанная
   с активным identity provider tenant'а, то есть token выпущен
   `federation:exchange`. Иначе `403 human_required` / `scope_not_granted` /
   `federation_required` с записью в audit (`people.authenticate`). Отключение
   человека, его identity, membership, провайдера или tenant закрывает путь
   сразу (`401 invalid_token`, в audit — что именно закрыто), не дожидаясь
   истечения token.
3. **Scope не выпускается другими путями.** Обмен PAT никогда не включает
   `iam:people` (явный запрос — `403 scope_not_allowed`, пустой — без него):
   PAT живёт неделями и authority администратора людей не переносит. Client
   credentials service account его тоже не получают, даже если bootstrap вписал
   scope в потолок.
4. **Кто администратор — решает политика IAM, а не запрос.** Federation
   выдаёт `iam:people` при трёх условиях сразу:

   - scope есть в allowed scopes audience `iam` tenant'а (`PATCH /audiences/iam`);
   - человек — член активной группы tenant'а `IAM_PEOPLE_ADMIN_GROUP`
     (по умолчанию `people-admins`). Саму группу заводит только bootstrap
     (`POST /groups`, `source = local`): federation-проекция группу с этим
     ключом не создаёт (пропускает её, пока группы нет), SCIM на создание
     отвечает `409`, а группа с этим ключом иного источника прав не даёт.
     Иначе IdP или SCIM-источник, заведя группу `people-admins`, раздавали бы
     права администратора. Членство в заведённой группе — любого источника:
     local, SCIM или federated — проекция групп IdP (`groupMappings`
     провайдера, `reconcile_group_projection`) приводит его к token IdP в той
     же транзакции, до выпуска token;
   - scope запрошен явно. Пустой запрос означает «всё, что разрешено audience»,
     **кроме** `iam:people` — его не выдаёт никогда.

   Это ограничение конкретного человека поверх audience, как `scope_ceiling`
   у `iam:agents`: `scope_ceiling` token не-администратора `iam:people` не
   содержит. Явный запрос не-администратора — `403 scope_not_allowed` с
   записью `federation.exchange` (`group:people-admins`). Guard проверяет
   членство и на каждом запросе: выход из группы закрывает путь сразу
   (`403 people_admin_required`). Заголовок или тело запроса authority не дают.
5. **Только люди.** По `iam:people` заводится только `kind = human`
   (`422 human_principal_required`); привязать identity и отключить можно
   только человека — агентами управляет владелец (`iam:agents`), service
   account и workload — bootstrap. Отказ пишется в audit. Чтение (`GET`,
   список) показывает principals всех видов: консоли нужно видеть организацию
   целиком (FR-013); после гейта п. 4 оно доступно только администраторам.
6. **Привязка identity по Bearer — только онбординг.** Иначе владелец
   `iam:people` привязал бы к чужому человеку (владельцу, другому
   администратору) пару `(issuer, subject)`, которую контролирует сам, и
   federation-вход усыновил бы её (`federation.identity_adopted`) — захват
   чужого Principal и всех его прав. Поэтому по Bearer привязка разрешена,
   только если одновременно:

   - цель — не сам вызывающий (`403 self_link_forbidden`);
   - issuer — активный identity provider tenant'а
     (`422 identity_provider_unknown`); read-only провайдер по-прежнему
     отвечает `409 identity_provider_managed`;
   - у цели нет ни одной external identity, включая отключённую
     (`409 principal_has_identity`);
   - у цели нет действующего credential — неотозванного и неистёкшего PAT
     или client secret service account (`409 principal_has_credential`):
     человек, входящий только по PAT, — не новичок;
   - цель не член группы администраторов людей любого статуса
     (`403 people_admin_protected`): identity к ней дала бы вызывающему
     второй вход администратора.

   Перед проверками строка цели блокируется (`SELECT … FOR UPDATE` на
   `principals`): две параллельные привязки к одному новичку сериализуются, и
   вторая видит identity первой. Уникальный индекс «одна активная identity на
   Principal» не годится — у человека законно бывает несколько (federation и
   канал). Тестами сериализация не закреплена: тесты идут на SQLite, где
   `FOR UPDATE` ничего не делает, а Postgres в CI нет.

   Всё прочее (вторая identity, чужой issuer, восстановление входа) — только
   bootstrap.
7. **`:disable` по Bearer** не отключает самого вызывающего
   (`409 self_disable_forbidden`) и членов группы администраторов людей
   (`403 people_admin_protected`) — это остаётся за bootstrap.
8. **Идемпотентность создания.** По `iam:people` заголовок `Idempotency-Key`
   обязателен (`400 idempotency_key_required`), для bootstrap — по желанию.
   Ключ принадлежит вызывающему: `tenant_memberships.idempotency_key` и
   `idempotency_actor` (`actor_ref` audit), уникальны тройкой
   `(tenant_id, idempotency_actor, idempotency_key)` (миграция
   `0007_people_scope`). Чужой ключ не находит чужого Principal. Повтор с тем
   же телом возвращает того же Principal с `Idempotency-Replayed: true`, с
   другим телом — `409 idempotency_key_reused` (с записью в audit).
9. **Audit с вызывающим.** `actor_ref` записей `principals.create`,
   `external_identities.link`, `principals.disable` и отзыва credentials —
   id Principal человека (для bootstrap — `bootstrap`); `reason` называет scope
   и external identity, через которую человек вошёл. `:disable` теперь пишет
   audit `principals.disable` и на bootstrap-пути. Отказы пишутся с
   `outcome = denied` и единым `resource_type = principal`: `resource_id` —
   Principal, к которому относилось действие (в том числе ненайденный —
   `principal_not_found` в привязке и отключении), а где цели нет (вход,
   создание) — сам вызывающий. Отказ `people.authenticate` пишется только
   после проверки подписи token: неподписанный мусор журнал не засоряет. Не
   пишутся и `403 tenant_mismatch` (запись легла бы в журнал чужого tenant из
   пути, куда предъявитель не входит, — любой token писал бы в любой tenant) и
   `401` на `sub` или `credential_id`, не являющиеся UUID (записи не на кого
   сослаться: `actor_ref` и `resource_id` — этот Principal).
10. **Список principals** — `GET /api/v1/tenants/{t}/principals?kind=&after=&limit=`,
   principals с активным membership по возрастанию id; ответ
   `{"items": [...], "next_after": <id>|null}`.
11. **Чтение external identities** (амендмент, TASK-000908). Консоли нужно
   ответить на два вопроса без bootstrap: «кому принадлежит вход
   `(issuer, subject)`» — например, после неоднозначного ответа привязки
   (`409 principal_has_identity` / `external_identity_exists`) — и «какими
   входами располагает человек». Маршруты с тем же допуском, что и остальные
   маршруты людей (bootstrap или Bearer `iam:people` по п. 2 и 4):

   - `GET /api/v1/tenants/{t}/external-identities?issuer=&subject=` — точное
     совпадение пары, ответ `{"items": [...]}` из нуля или одного элемента.
     Оба параметра обязательны (`422`). Пара уникальна глобально, но
     видна только identity Principal с активным membership этого tenant'а:
     identity чужого tenant'а даёт пустой ответ, а не `404`/`403`, — «нет»
     и «есть, но не у вас» не различаются;
   - `GET /api/v1/tenants/{t}/principals/{p}/external-identities` — identities
     Principal любого статуса по времени привязки; Principal вне tenant'а —
     `404 principal_not_found`.

   Элемент — `{id, principal_id, issuer, subject, status}` (snake_case, как
   `PrincipalView` и ответ привязки); `status` — статус
   самой identity (`active`/`disabled`), а не Principal: `:disable` identity не
   меняет, статус человека отдаёт `GET …/principals/{p}`. Служебные поля
   (провайдер, источник провижининга, последний вход и `acr`) не отдаются.
   Список identities Principal — без пагинации: их число у одного Principal
   ограничено (federation, провижининг, каналы — единицы).

   Видны identities любого источника, включая канальные (`source = channel`,
   issuer канала и `subject` — идентификатор пользователя в мессенджере,
   например Telegram id). Это персональные данные, и администратор людей
   видит их осознанно: связать человека с его входами — ровно его задача, а
   bootstrap видел их и раньше.

   Защита групп привилегированных scope (п. 6–7, ADR-0003) ограничивает
   **изменения**, а не чтение: по п. 5 администратор людей и так видит всех
   principals tenant'а, включая других администраторов, а знание пары
   `(issuer, subject)` authority не даёт — вход требует upstream token IdP.
   Поэтому identities защищённых principals (и свои) читаются без
   `people_admin_protected`. Чтение в audit не пишется, как и прочие `GET`
   людей; отказ допуска (`people.authenticate`) пишется guard'ом как прежде.
   `403 tenant_mismatch` — у token другого tenant'а.

12. **`:enable` — обратная операция к `:disable`** (амендмент, TASK-000907).
   До него отключённого человека вернуть было нечем: ни bootstrap, ни
   администратор людей не могли снова открыть ему вход, оставалось заводить
   нового Principal и терять историю. Маршрут
   `POST /api/v1/tenants/{t}/principals/{p}:enable` — с тем же допуском, что и
   `:disable` (bootstrap или Bearer `iam:people` по п. 2 и 4), — переводит
   Principal в `active` и отвечает
   `{principalId, status, previousStatus, enabledAt}`.

   - **Отозванное не восстанавливается.** PAT и client secret, отозванные при
     отключении, остаются отозванными (`revoked_at` не снимается): обмен даёт
     прежний `401 invalid_token`. Access token, выпущенные до включения, тоже
     не оживают: IAM запоминает момент включения, и guard `iam:people`
     отвергает token с `iat` раньше него (`401 invalid_token`, в audit
     `closed:session`) — только на этом пути. Resource service получают в
     событии `principal.enabled` поле `sessionsNotBefore` для той же проверки
     у себя, но пока его не потребляют; без неё окно ограничено TTL access
     token (`IAM_TOKEN_TTL_SECONDS`), а
     отрицательный revocation-кэш `platform-auth-sdk` — своим
     `stale_after_seconds`. Человек входит заново через IdP, а PAT для
     локального harness выпускается заново, после свежего входа.
   - **External identities остаются привязанными** и статуса не меняют:
     `:disable` их не трогал, поэтому после `:enable` federation-вход той же
     парой `(issuer, subject)` работает сразу. Identity, отключённая отдельно
     (SCIM, bootstrap), остаётся отключённой.
   - **Защита по аналогии с п. 7.** По Bearer нельзя включить самого себя
     (`409 self_enable_forbidden`; отключённый человек сюда и не войдёт, но
     правило не должно зависеть от порядка проверок). Члена группы
     привилегированного scope из реестра ADR-0003 (`people-admins`,
     `fleet-admins` и настроенные) — членство любого статуса — включает
     только член **той же** группы: включение возвращает цели authority этой
     группы, и администратор людей без `fleet:admin` не должен возвращать
     чужой `fleet:admin` (`403 people_admin_protected`, `reason` —
     `group:<ключ>`). Администратор людей включает другого администратора
     людей: он сам член `people-admins`. Отключить администратора по Bearer
     по-прежнему нельзя (п. 7) — асимметрия намеренна: отключение отнимает
     authority, включение её возвращает. Только люди
     (`422 human_principal_required`), как в п. 5; bootstrap включает любого.
   - **Чужой lifecycle не трогается.** `paused` — не отключение:
     `409 principal_paused`. Человека, которого отключил источник
     провижининга (SCIM-запись с `active: false`), включает он же
     (`active: true`), иначе IAM разошёлся бы с кадровой системой:
     `409 principal_provisioned`. Principal без активного membership
     tenant'а — `404 principal_not_found`. Исходные статусы перечислены
     явно: `:enable` включает только `disabled` (`active` — no-op), любой
     иной статус — `409 principal_status_not_enableable` (`reason`
     `status:<статус>`), а не молчаливое включение (TASK-000972).
   - **SCIM-реактивация — то же включение** (TASK-000972). `active: true`
     от источника провижининга пишет запись в `principal_enablements` и
     событие `principal.enabled` с `sessionsNotBefore`, как `:enable`: иначе
     token, выпущенный до отключения в кадровой системе, после реактивации
     снова проходил бы guard `iam:people`. Источник — хозяин lifecycle
     своего человека и включает его из любого неактивного статуса.
   - **Идемпотентность.** По Bearer `Idempotency-Key` обязателен
     (`400 idempotency_key_required`), для bootstrap — по желанию. Ключ
     принадлежит вызывающему, как в п. 8, и хранится в записи включения
     `principal_enablements` (уникальна тройка
     `(tenant_id, idempotency_actor, idempotency_key)`, миграция
     `0008_principal_enable`). Повтор с тем же ключом отвечает сохранённым
     результатом с `Idempotency-Replayed: true` и **текущим** `status`: если
     человека после первого включения снова отключили, повтор его не
     включает. Тот же ключ для другого Principal — `409
     idempotency_key_reused` (с записью в audit). Включение активного
     Principal — no-op: `previousStatus: active`, без события и без сдвига
     момента включения. Отдельная таблица здесь оправдана, в отличие от
     создания (отвергнутый вариант ниже): у включения нет своей строки, где
     ключ был бы уникален, а момент включения нужен guard'у.
   - **Audit и события.** `principals.enable` с `actor_ref` вызывающего и
     `reason` `previous:<статус>` плюс scope и identity входа (п. 9); отказы —
     `outcome = denied`, `resource_type = principal`. В outbox —
     `principal.enabled` с `principalId` и `sessionsNotBefore`, только при
     фактическом переходе. Переход — условный `UPDATE … WHERE status =
     'disabled'`: из двух параллельных включений (например, двух bootstrap
     без ключа) строку меняет одно, оно же пишет момент включения и событие;
     второе видит `active` и отвечает no-op (`previousStatus: active`), а если
     Principal параллельно ушёл в иной статус — `409 principal_conflict`
     (TASK-000972).

## Последствия

- Контракт токена не меняется: `platform-auth-sdk` видит те же claims,
  contract-тест сверх существующих не нужен. Потребитель `iam:people` — сам
  IAM.
- Развёртыванию нужно добавить `iam:people` в allowed scopes audience `iam`
  (R004, `deploy/bootstrap.py`) и запрашивать его при `federation:exchange`
  для консоли.
- Развёртыванию нужно завести группу `people-admins` bootstrap'ом
  (`POST /groups`) и наполнить её: mapping группы IdP в `groupMappings`
  провайдера (R004, `deploy/bootstrap.py`) либо local/SCIM членство. Без
  заведённой bootstrap'ом группы `iam:people` не получит никто — безопасное
  умолчание. SCIM-группа, чьё имя даёт ключ `people-admins`, не создаётся
  (`409`): её нужно переименовать в источнике или связать членство через
  `groupMappings`.
- Администратор людей не может отключить себя и другого администратора, а
  привязать identity — только новичку без identity. Разжаловать
  администратора — убрать его из группы в IdP (действует при следующем входе
  через проекцию, а для уже выданного token — сразу, если членство снято в
  IAM) или отключить bootstrap'ом.
- Отключённого человека администратор людей возвращает `:enable`
  (п. 12): вход через IdP открывается сразу, PAT и прежние сессии — нет.
  Консоли нужно передавать `Idempotency-Key` и после включения предложить
  человеку войти заново; потребителям событий — учитывать
  `principal.enabled.sessionsNotBefore`.
- Повторная привязка по Bearer отвечает `409 principal_has_identity` (у
  человека уже есть identity), по bootstrap — `409 external_identity_exists`,
  как и раньше. Для потока консоли оба ответа после неоднозначного первого
  шага означают «identity у человека уже есть».

## Отвергнутые варианты

- **Bootstrap-токен в BFF консоли** — нарушает ст. VI: администрирование всего
  IAM (audiences, service accounts, PAT) вместо людей tenant'а.
- **Scope через PAT** — долгоживущий credential локального harness стал бы
  ключом администратора людей; federation-вход короткий и отзывается по
  identity.
- **Роль администратора в заголовке или теле** — authority из запроса, а не из
  подписанного token и политики IAM.
- **Отдельная таблица идемпотентности** — ключ создания принадлежит membership
  tenant'а: там же, где он уникален.
