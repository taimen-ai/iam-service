# ADR-0004 (IAM): почта федеративной identity, поиск человека по почте и identity подключений

*English title: IAM — verified e-mail on federated identities, people lookup by
e-mail, connection identities and the `iam:identities.link` scope.*

- Статус: принято ревью владельца (фича integrations-connections, пункт I002,
  TASK-000989; plan фичи одобрен владельцем на воротах дизайна 2026-09-29,
  решения plan Р8 и Р9, дизайн §3). Вступает в силу вливанием ветки задачи,
  которое происходит только после одобрения ревью.
- Требования: FR-010, SC-009 spec фичи; конституция, ст. V, VI, IX.
- Амендирует: [ADR-0002](0002-iam-people-scope.md) п. 6 и 11 (привязка и
  чтение identity подключений по `iam:people`),
  [ADR-0003](0003-privileged-scopes.md) п. 8 (`iam:identities.link` — scope
  без группы). Прецедент держателя-не-человека:
  [ADR-0001](0001-iam-agents-scope.md) (`iam:agents`).
- Границы: верхнеуровневые ADR-0012 (Platform Access Token) и ADR-0013 (IAM
  отделён от entitlement и доменной авторизации); TAI-ADR-0061 (подключения).
  Формат access token и его claims не меняются.
- Реализация: I014 (почта и поиск, п. 1–2), I015 (identity подключений и
  scope, п. 3–6). Этот документ — контракт для обеих задач и для
  потребителей: коннектора (I026) и консоли (I030). Guard п. 5
  (`identities.authenticate`: bootstrap и человек — через guard
  `iam:people`, агент — по PAT) реализован в I014, потому что его требует
  поиск п. 2; I015 подключает его к маршрутам п. 4 и добавляет проверку
  issuer. Миграция I014 — `0009_identity_email` (п. 1), I015 продолжает
  цепочку после неё: `0010_connection_identities` (п. 3).
- Уточнения реализации I015 (TASK-001002), в рамках решения:
  - сверка ключа подключения (п. 3): на ревизии control-plane, закреплённой
    суперпроектом, ресурса `Connection` (CP-ADR-0079) ещё нет — ни в `main`,
    ни в `feature/integrations-connections`; шаблон
    `[a-z0-9._-]{1,200}` оставлен как есть. Сверку повторяет задача,
    вливающая `Connection` в ядро;
  - отказ агенту `issuer_not_allowed` на чтении списка (п. 4.3) пишется в
    audit действием `external_identities.find` (`resource_id` — агент), на
    привязке и снятии — `external_identities.link` и
    `external_identities.unlink` (`resource_id` — Principal пути);
  - `reason` успешной привязки — `issuer:<issuer>` плюс scope и credential
    вызывающего и для `manual`: `scope:iam:people identity:<id>` человека,
    `scope:iam:identities.link pat:<id>` агента, у bootstrap — только issuer.
- Амендмент 2026-09-30, TASK-001041 (ревью I014): поиск п. 2 видит и
  identity `source = provisioned` — человека из SCIM, вошедшего через IdP;
  фильтр access log сравнивает декодированное имя параметра (п. 2);
  интернационализированные домены не нормализуются (п. 1).
- Уточнения по ревью I015 (TASK-001042), в рамках решения:
  - `DELETE` (п. 4.2) сверяет tenant issuer'а с tenant'ом пути для любого
    вызывающего, включая bootstrap (`422 issuer_tenant_mismatch`), как
    привязка (п. 3). Такая identity попадает в базу только в обход API, но
    снимать её из чужого tenant'а незачем;
  - агенту на `DELETE` проверка issuer (`403 issuer_not_allowed`) идёт
    раньше, чем `404 external_identity_not_found` за чужого Principal или
    tenant: 404 остаётся только для identity, которой нет вовсе;
  - правило онбординга ADR-0002, п. 6, «у цели нет ни одной external
    identity» не считает identity подключений: человек, сопоставленный
    только с CRM, получает ручную привязку входа.

## Контекст

Задачи платформы уходят во внешнюю систему (CRM) только сопоставленным людям,
а закрытие задачи во внешней системе засчитывается человеку платформы
(сценарий 3 spec). Для этого пользователь внешней системы должен быть связан с
человеком организации — и эта связь по ст. III живёт в IAM как external
identity, рядом со входами через IdP и каналы.

Сопоставлять нужно автоматически при однозначной рабочей почте (FR-010,
SC-009), иначе — решением администратора. Сегодня этого не сделать:

- IAM не хранит почту вовсе — ни у Principal, ни у identity;
- найти человека по почте нельзя;
- привязать identity по Bearer может только администратор людей (`iam:people`,
  ADR-0002), и только новичку без единой identity (п. 6) — а сопоставляемые
  люди как раз уже входят через IdP;
- коннектор — агент, а `iam:people` принимается только от человека,
  вошедшего через federation.

Почему отдельный ADR, а не амендмент ADR-0002: здесь появляется второй
держатель прав на identity — агент со своим scope и своим guard'ом, — новое
понятие (источник `connection`) и новые данные (почта). ADR-0002 описывает
людей, которыми управляет человек-администратор; вписать туда агента значило
бы переписать его п. 2–6. Амендменты ADR-0002 и ADR-0003 ограничены ссылками
на этот документ.

## Решение

### 1. Почта на федеративной identity

- Колонка `external_identities.email` — `VARCHAR(320) NULL`, индекс
  `ix_external_identities_email`, **не** уникальна: один ящик законно бывает
  у двух identity (два IdP, пересоздание пользователя в IdP). Миграция —
  следующая в цепочке после `0008_principal_enable`.
- Пишется **только** при входе через federation — у identity, найденной или
  созданной входом: `federated` или, у человека из SCIM, `provisioned`
  (п. 2). Маршруты `federation:authenticate` и `federation:exchange` оба идут
  через общий `federate` → `link_identity`, запись там, и для новой, и для
  существующей identity. Источник — стандартные claims OIDC upstream token:
  `email` и `email_verified`. Имена claims не настраиваются у провайдера:
  настраиваемое имя позволило бы ошибкой конфигурации сделать ключом
  сопоставления неподтверждённый атрибут.
- Условие — `email_verified` равен JSON `true` (булево; строка `"true"` не
  считается). Иначе, и если `email` нет или он некорректен, колонка
  **очищается** (`NULL`): источник истины — текущий token IdP, и почта,
  переставшая быть подтверждённой, сразу перестаёт находить человека.
- Нормализация: пробелы по краям срезаются, адрес целиком приводится к нижнему
  регистру; ровно один `@`, непустые части, длина ≤ 320. Некорректный адрес
  считается отсутствующим. Тем же правилом нормализуется параметр поиска
  (п. 2).
- Интернационализированные домены (IDN) **не** нормализуются (амендмент
  TASK-001041): `пример.рф` и его punycode `xn--e1afmkfd.xn--p1ai` — разные
  адреса и друг друга не находят; Unicode в локальной части тоже сравнивается
  как есть. Коннектор ищет адрес в той форме, в какой его подтверждает IdP
  tenant'а; если внешняя система отдаёт другую форму, приводить её —
  дело коннектора, IAM вторую форму не подбирает.
- Другие источники почту **не** пишут: SCIM (`emails` не подтверждены token
  IdP), привязка bootstrap'ом, каналы, подключения. Кто ни разу не входил
  через IdP, сопоставляется администратором вручную (plan Р8).
- Почта — ключ поиска, а не атрибут для чтения. Её нет ни в
  `ExternalIdentityView`/`ExternalIdentityItem`, ни в `PrincipalView`, ни в
  событиях outbox, ни в audit. Claims access token IAM не меняются.
- У существующих identity почта появляется при следующем входе человека.

### 2. Поиск человека по почте

`GET /api/v1/tenants/{t}/principals:by-email?email=<адрес>`

- Допуск: bootstrap, Bearer `iam:people` (ADR-0002, п. 2 и 4) или Bearer
  агента с `iam:identities.link` (п. 5).
- `email` обязателен, 3…320 символов; после нормализации (п. 1) некорректный —
  `422 invalid_email`.
- Возвращает Principals, у которых одновременно:
  - `kind = human` и `status = active`;
  - активный membership tenant'а `t`;
  - есть external identity `source` ∈ {`federated`, `provisioned`},
    `status = active`, с этой почтой, **и её identity provider — активный
    провайдер tenant'а `t`**: почту подтвердил IdP этого tenant'а, а не
    чужого.
- Почему `provisioned` (амендмент TASK-001041): identity человека из SCIM
  заводится сразу с провайдером, и при входе federation её усыновляет, не
  меняя `source` (source становится `federated` только у identity без
  провайдера). Почта у неё пишется тем же входом (п. 1), а без
  `provisioned` в условии поиск её не видел бы — в tenant'ах со SCIM
  автосопоставление FR-010/SC-009 не работало бы. Ослабления нет: почту
  по-прежнему пишет только federation-вход, SCIM `emails` в колонку не
  попадают, а `manual`, `channel` и `connection` почты не имеют и в условие
  не входят.
- Ответ `{"items": [PrincipalView, ...]}` — без повторов, по возрастанию `id`,
  без пагинации (совпадений единицы). Ноль, одно или несколько совпадений —
  все отдаются как есть; что делать с неоднозначностью, решает вызывающий
  (сценарий 3: несколько совпадений — решение администратора).
- Агенты, service account, workload, отключённые и приостановленные люди не
  возвращаются никогда.
- Чтение в audit не пишется, как прочие `GET` людей (ADR-0002, п. 11): запись
  без адреса бесполезна, а с адресом положила бы персональные данные в журнал.
  В audit пишется результат сопоставления — привязка (п. 4). Отказ допуска
  пишется guard'ом (`people.authenticate` или `identities.authenticate`).
- **Адрес в query string и журналы запросов.** Форма `GET ?email=` задана
  plan §3, поэтому адрес виден всему, что пишет URI запроса. Требования к
  реализации и развёртыванию (п. «Последствия»):
  - I014: access log uvicorn (`CMD` в `Dockerfile` пишет его по умолчанию)
    не должен содержать значение `email` — фильтр логгера `uvicorn.access`
    заменяет значение параметра `email` на `[redacted]` в строке запроса.
    Имя параметра сравнивается после декодирования тем же `parse_qsl`, что и
    у Starlette (без учёта регистра): `?e%6Dail=…` доходит до маршрута как
    `email` и вырезается так же (амендмент TASK-001041). Тест проверяет, что
    после запроса к `principals:by-email` — и с закодированным именем
    параметра — адреса в записи журнала нет. Собственные логи IAM адрес не
    пишут (в том числе в тексте ошибки `422 invalid_email`);
  - периметр (Caddy, JSON-лог): для маршрута IAM — фильтр лога, удаляющий
    параметр `email` из `request.uri` (`format filter`, `query { delete email }`),
    или отключённый лог этого маршрута;
  - остаточный риск принимается: адрес видят TLS-терминирующие узлы между
    агентом и периметром и трассировка, если её включат. Почта в запросе —
    рабочий адрес, который внешняя система и так отдаёт коннектору.

### 3. Источник `connection`

- `external_identities.source` принимает `connection` (расширение
  check-ограничения той же миграцией). Такая identity — пользователь
  подключённой внешней системы, сопоставленный с человеком.
- **issuer** — `connection:<tenantId>:<connectionKey>`:
  - `tenantId` — UUID tenant'а в каноническом виде (нижний регистр, с
    дефисами);
  - `connectionKey` — ключ ресурса `Connection` ядра (CP-ADR-0079), 1…200
    символов `[a-z0-9._-]`, без `:`. IAM существование подключения в ядре не
    проверяет: учёт подключений — ядро (ст. III), IAM хранит только пары;
  - форма ключа в IAM должна быть не уже формы ключа `Connection` в ядре:
    иначе подключение, которое ядро приняло, нельзя будет сопоставить. На
    момент этого ADR CP-ADR-0079 в control-plane ещё не влит; I015 сверяет
    шаблон с кодом ядра (`Connection.key`) и, если он отличается, приводит
    шаблон IAM к нему амендментом этого пункта (`:` в ключе исключается
    всегда — это разделитель issuer);
  - иная форма после префикса `connection:` — `422 invalid_connection_issuer`.
- **subject** — идентификатор пользователя во внешней системе строкой, как её
  отдаёт внешняя система (1…500 символов); IAM его не толкует.
- **Уникальность** пары `(issuer, subject)` глобальная, как для всех identity;
  tenant входит в issuer, как у каналов (`iam:channel:<канал>:<tenant>`).
  Пользователь внешней системы сопоставлен не более чем с одним человеком;
  у человека может быть несколько таких identity (несколько подключений,
  несколько учёток).
- **Источник выводится из issuer, а не выбирается вызывающим.** Привязка с
  префиксом `connection:` — всегда `source = connection`, без
  `identity_provider_id` и `provisioning_source_id`; без префикса — как
  раньше (`manual`).
- **Tenant issuer'а — tenant пути** для любого вызывающего, включая bootstrap:
  иначе `422 issuer_tenant_mismatch` (агенту — `403 issuer_not_allowed`,
  п. 5).
- **Цель — человек** для любого вызывающего, включая bootstrap
  (`422 human_principal_required`): identity подключения сопоставляет людей.
- **Не вход.** Identity подключения не credential: ни один путь выпуска token
  её не принимает. Federation ищет identity по issuer провайдера, канал — по
  `iam:channel:*`, guard `iam:people` требует identity с провайдером.
  Чтобы так было и дальше, префикс `connection:` **зарезервирован** за
  identity подключений. Резерв держит уже существующая проверка
  `POST /api/v1/tenants/{t}/identity-providers`: issuer провайдера обязан
  начинаться с `http://` или `https://`, иначе `422 invalid_issuer` —
  issuer `connection:…` отвергается ею, отдельный код ошибки не вводится.
  Маршрута смены issuer у провайдера нет. Поэтому federation не может ни
  войти такой парой, ни «усыновить» её (`federation.identity_adopted`). Это
  инвариант: ослабить проверку `invalid_issuer` (например, разрешить issuer
  не-URL) можно только вместе с явным отказом по префиксу `connection:`,
  стоящим до записи провайдера. Миграция проверяет, что провайдеров с таким
  issuer нет, и падает с понятной ошибкой, если есть (данные могли попасть в
  базу в обход API).
- **Статус.** Identity подключения создаётся `active` и не отключается:
  снятие сопоставления — удаление (п. 4), чтобы пару можно было отдать
  другому человеку. Отключение Principal identity не трогает (как ADR-0002,
  п. 12); отключённый человек не находится поиском (п. 2), а коннектор не
  проецирует ему задач.

### 4. Маршруты identity подключений

Все четыре маршрута принимают bootstrap, Bearer `iam:people` и Bearer агента
с `iam:identities.link`; ограничения агента — п. 5.

1. **`POST /api/v1/tenants/{t}/principals/{p}/external-identities`**
   (существующий, тело `{issuer, subject}`, ответ `201 ExternalIdentityView`).
   Для issuer `connection:`:
   - цель — человек с активным membership tenant'а (иначе
     `404 principal_not_found`); по Bearer (человек или агент) — ещё и
     `status = active` (`409 principal_not_active`): сопоставлять отключённого
     незачем, bootstrap может;
   - **правила онбординга ADR-0002, п. 6, не применяются**, кроме запрета
     привязки к себе (`403 self_link_forbidden` по Bearer `iam:people`). Эти
     правила защищают от захвата входа: пары, которую federation усыновит.
     Identity подключения входа не даёт (п. 3), поэтому её можно привязать
     человеку, у которого уже есть identity, credential или членство в группе
     привилегированного scope. Запрет на себя остаётся: администратор, сам
     назначивший себе пользователя внешней системы, получал бы в зачёт работу,
     закрытую в ней чужими руками; себя ему сопоставит коннектор по почте или
     другой администратор;
   - занятая пара — `409 external_identity_exists`, как раньше. Повтор
     сопоставления не дублирует его: коннектор перед привязкой читает список
     (п. 4.3).
   - Событие `external_identity.linked` получает поля `source` и `issuer`
     (добавление; прежние поля остаются) — во всех трёх местах, где оно
     пишется, чтобы потребитель различал сопоставления, не читая identity:
     - этот маршрут — `source` = `connection` или `manual` (как выведен из
       issuer), `issuer` — из тела;
     - federation (`link_identity`, новая identity) — `source = federated`,
       `issuer` — issuer провайдера; поле `identityProvider` остаётся;
     - SCIM (`scim/provisioning.py`) — `source = provisioned`, `issuer` —
       issuer провайдера источника.
     Во всех случаях issuer — URL провайдера, `iam:channel:…` или
     `connection:<tenant>:<key>`, персональных данных в нём нет; subject и
     почта в событие не попадают. Усыновление существующей identity
     federation'ом (`federation.identity_adopted`) события не пишет, как и
     сейчас.
     Audit `external_identities.link`, `actor_ref` — вызывающий (человек,
     агент или `bootstrap`), `reason` — `issuer:<issuer>` плюс scope и
     credential, по которому вызывающий вошёл.
2. **`DELETE /api/v1/tenants/{t}/principals/{p}/external-identities/{id}`**
   (новый) — снять сопоставление.
   - Только identity `source = connection`, для любого вызывающего:
     иначе `422 connection_identity_required`. Identity входа (IdP, SCIM,
     каналы) снимаются, как и прежде, своими путями (SCIM, bootstrap,
     отвязка канала).
   - Identity должна принадлежать Principal `p` с активным membership tenant'а
     `t`: иначе `404 external_identity_not_found`. Агенту проверка issuer
     (п. 5) идёт раньше: существующая identity чужого пространства имён —
     `403 issuer_not_allowed`, даже если она не принадлежит `p`.
   - Tenant issuer'а — tenant пути для любого вызывающего, включая bootstrap:
     иначе `422 issuer_tenant_mismatch` (агенту — `403 issuer_not_allowed`).
   - По Bearer `iam:people` — не свою (`403 self_link_forbidden`).
   - Строка удаляется, пара освобождается. Ответ `204`. Событие
     `external_identity.unlinked` `{externalIdentityId, principalId, source,
     issuer}`; audit `external_identities.unlink` с вызывающим, как в п. 4.1.
3. **`GET /api/v1/tenants/{t}/external-identities?issuer=&subject=&after=&limit=`**
   (существующий, ADR-0002 п. 11) — `subject` становится необязательным.
   - С `subject` — как раньше: точная пара, 0 или 1 элемент.
   - Без `subject` — все identity с этим issuer, чей Principal имеет активный
     membership tenant'а `t`, по возрастанию `id`; `limit` 1…200 (по
     умолчанию 100), `after` — `id` последнего элемента предыдущей страницы.
   - Ответ — `{"items": [...], "next_after": <id>|null}`: поле `next_after`
     добавляется (с `subject` — всегда `null`). Элемент — прежний
     `ExternalIdentityItem`, почты в нём нет.
   - По `iam:people` и bootstrap — любой issuer (администратор людей и так
     видит все identity, ADR-0002 п. 11); агент — только свой (п. 5).
4. **`GET /api/v1/tenants/{t}/principals:by-email`** — п. 2.

Остальные маршруты людей (`POST/GET …/principals`, `GET …/principals/{p}`,
`GET …/principals/{p}/external-identities`, `:disable`, `:enable`) агенту
недоступны: их guard по-прежнему требует человека (`403 human_required`).

### 5. Scope `iam:identities.link`

- Scope audience самого IAM: `IAM_IDENTITIES_LINK_SCOPE` (по умолчанию
  `iam:identities.link`), audience — `IAM_PEOPLE_AUDIENCE` (`iam`), тот же,
  что у `iam:people`.
- **Держатель — только агент.** Guard (`identities.authenticate`) принимает
  Bearer с `principal_type = agent`, этим scope и tenant, совпадающим с путём
  (иначе `403 tenant_mismatch`, без записи в audit — ADR-0002, п. 9). На каждом
  запросе проверяется, что `credential_id` token — PAT этого агента, не
  отозванный и не истёкший, а агент, его membership и tenant активны; иначе
  `401 invalid_token` с `closed:<что закрыто>` в audit. Отзыв PAT или
  отключение агента закрывают путь сразу, не дожидаясь истечения token.
- Человек с этим scope ничего не получает: на маршрутах п. 4 человек проходит
  guard `iam:people` (без `iam:people` — `403 scope_not_granted`). Service
  account и workload — `403 agent_required`.
- **Действует только на issuer с префиксом `connection:<tenant token>:`**
  (п. 3), только в tenant'е token и только в четырёх маршрутах п. 4. Любой
  другой issuer — identity входа (IdP, например Keycloak), канала (Telegram),
  подключения чужого tenant'а, произвольная строка — `403 issuer_not_allowed`
  с записью в audit (`outcome = denied`, `reason` — `issuer:<issuer>`). Эта
  проверка идёт до проверки формы issuer и цели: агенту чужие пространства
  имён не отвечают ничем, кроме отказа.
- **Не привилегированный scope** в смысле ADR-0003: в реестр не вносится.
  Агент получает его только обменом PAT, а привилегированные scope PAT не
  приносит никогда (ADR-0003, п. 5). Пустой запрос `federation:exchange` может
  принести его человеку, если scope есть в allowed scopes audience `iam`, —
  это безвредно: guard принимает его только от агента.
- **Сужение до конкретных подключений агента — вне этого решения** (plan §3):
  агент с этим scope сопоставляет пользователей любого подключения своего
  tenant'а. Кандидат на отдельное решение — сверка issuer с
  `Agent.spec.connections` в ядре или claim подключений в token; ни то, ни
  другое не нужно первому провайдеру, у которого одно подключение на
  коннектор.
- **Как агент получает scope** — существующая цепочка ADR-0001, без новых
  путей выпуска:
  1. bootstrap добавляет `iam:identities.link` в allowed scopes audience `iam`
     tenant'а (`PATCH /audiences/iam`);
  2. потолок service account владельца (`fleet-controller`) содержит этот
     scope, а его audiences — `iam`: потолок PAT агента — подмножество потолка
     владельца (ADR-0001, п. 5);
  3. ревизия агента объявляет `identity.iam {audiences: [..., iam],
     scopeCeiling: [..., iam:identities.link]}` (CP-ADR-0073), и владелец
     выпускает PAT агента с этим потолком
     (`POST …/agents/{id}/platform-access-tokens`);
  4. агент обменивает PAT на token audience `iam`
     (`POST /api/v1/platform-access-tokens:exchange`) и получает scope.

### 6. Границы scope: примеры

Tenant агента — `T` (`3f6c2b1e-…`), чужой tenant — `U`, ключ подключения —
`crm-main`, issuer IdP tenant'а — `https://sso.example.com/realms/acme`.
Token агента: audience `iam`, `tenant_id = T`, scope `iam:identities.link`.

| Запрос агента | Ответ |
|---|---|
| `GET /tenants/T/principals:by-email?email=Anna@Example.com` | `200`, люди `T` с подтверждённой почтой `anna@example.com` |
| `GET /tenants/T/external-identities?issuer=connection:T:crm-main` | `200`, сопоставления подключения, страницами |
| `GET /tenants/T/external-identities?issuer=connection:T:crm-main&subject=8123` | `200`, 0 или 1 элемент |
| `POST /tenants/T/principals/P/external-identities` `{issuer: connection:T:crm-main, subject: 8123}` | `201`, `source = connection` |
| `DELETE /tenants/T/principals/P/external-identities/{id}` (identity `connection:T:crm-main`) | `204` |

| Запрещённый запрос агента | Ответ |
|---|---|
| `POST …/external-identities` `{issuer: https://sso.example.com/realms/acme, subject: …}` — identity входа IdP | `403 issuer_not_allowed` |
| `POST …/external-identities` `{issuer: iam:channel:telegram:T, subject: …}` — вход через канал | `403 issuer_not_allowed` |
| `POST /tenants/T/…/external-identities` `{issuer: connection:U:crm-main, …}` — подключение чужого tenant'а | `403 issuer_not_allowed` |
| `GET /tenants/T/external-identities?issuer=https://sso.example.com/realms/acme` | `403 issuer_not_allowed` |
| `DELETE …/external-identities/{id}` identity входа IdP | `403 issuer_not_allowed` |
| любой маршрут с путём `/tenants/U/…` | `403 tenant_mismatch` |
| `POST …/external-identities` `{issuer: connection:T:, …}` или `connection:T:a:b` | `422 invalid_connection_issuer` |
| `POST /tenants/T/principals/A/external-identities` с `connection:T:crm-main`, `A` — агент | `422 human_principal_required` |
| то же, человек `P` отключён | `409 principal_not_active` |
| то же, пара `(connection:T:crm-main, 8123)` уже у другого человека | `409 external_identity_exists` |
| `POST /tenants/T/principals`, `GET /tenants/T/principals/P`, `GET …/principals/P/external-identities`, `:disable`, `:enable` | `403 human_required` |

| Запрос не-агента со scope `iam:identities.link` | Ответ |
|---|---|
| человек без `iam:people` на любом маршруте п. 4 | `403 scope_not_granted` |
| service account или workload | `403 agent_required` |

По `iam:people` и bootstrap те же маршруты работают на любом issuer, кроме
ограничений п. 3–4: чужой tenant в `connection:` — `422
issuer_tenant_mismatch` (и на привязке, и на удалении), удаление identity
входа — `422 connection_identity_required`, привязка identity входа — прежние
правила ADR-0002, п. 6; identity подключения цели им не мешает.

### 7. OpenAPI

Фрагменты — только добавления к контракту IAM; существующие ответы не
меняются, кроме необязательного `subject` и поля `next_after` (п. 4.3).

```yaml
paths:
  /api/v1/tenants/{tenant_id}/principals:by-email:
    get:
      operationId: findPrincipalsByEmail
      summary: Люди tenant'а по почте, подтверждённой IdP tenant'а при входе
      security: [{bootstrapToken: []}, {iamBearer: ["iam:people"]}, {iamBearer: ["iam:identities.link"]}]
      parameters:
        - {$ref: "#/components/parameters/TenantId"}
        - name: email
          in: query
          required: true
          schema: {type: string, minLength: 3, maxLength: 320}
          description: Нормализуется — пробелы по краям срезаются, адрес в нижний регистр.
      responses:
        "200":
          content:
            application/json:
              schema: {$ref: "#/components/schemas/PrincipalByEmailPage"}
        "401": {description: "unauthorized | invalid_token"}
        "403": {description: "tenant_mismatch | human_required | scope_not_granted | people_admin_required | federation_required | agent_required"}
        "404": {description: tenant_not_found}
        "422": {description: invalid_email}

  /api/v1/tenants/{tenant_id}/external-identities:
    get:
      operationId: findExternalIdentities
      summary: External identities tenant'а по issuer (и subject)
      security: [{bootstrapToken: []}, {iamBearer: ["iam:people"]}, {iamBearer: ["iam:identities.link"]}]
      parameters:
        - {$ref: "#/components/parameters/TenantId"}
        - {name: issuer, in: query, required: true, schema: {type: string, minLength: 1, maxLength: 500}}
        - {name: subject, in: query, required: false, schema: {type: string, minLength: 1, maxLength: 500}}
        - {name: after, in: query, required: false, schema: {type: string, format: uuid}}
        - {name: limit, in: query, required: false, schema: {type: integer, minimum: 1, maximum: 200, default: 100}}
      responses:
        "200":
          content:
            application/json:
              schema: {$ref: "#/components/schemas/ExternalIdentityPage"}
        "403": {description: "tenant_mismatch | issuer_not_allowed | …guard"}
        "404": {description: tenant_not_found}

  /api/v1/tenants/{tenant_id}/principals/{principal_id}/external-identities:
    post:
      operationId: linkExternalIdentity
      summary: Привязать identity; issuer `connection:<tenant>:<key>` — сопоставление подключения
      security: [{bootstrapToken: []}, {iamBearer: ["iam:people"]}, {iamBearer: ["iam:identities.link"]}]
      requestBody:
        required: true
        content:
          application/json:
            schema: {$ref: "#/components/schemas/ExternalIdentityCreate"}
      responses:
        "201":
          content:
            application/json:
              schema: {$ref: "#/components/schemas/ExternalIdentityView"}
        "403": {description: "issuer_not_allowed | self_link_forbidden | people_admin_protected | …guard"}
        "404": {description: principal_not_found}
        "409": {description: "external_identity_exists | principal_not_active | principal_has_identity | principal_has_credential | identity_provider_managed"}
        "422": {description: "invalid_connection_issuer | issuer_tenant_mismatch | human_principal_required | identity_provider_unknown"}

  /api/v1/tenants/{tenant_id}/principals/{principal_id}/external-identities/{identity_id}:
    delete:
      operationId: unlinkConnectionIdentity
      summary: Снять сопоставление identity подключения
      security: [{bootstrapToken: []}, {iamBearer: ["iam:people"]}, {iamBearer: ["iam:identities.link"]}]
      parameters:
        - {$ref: "#/components/parameters/TenantId"}
        - {name: principal_id, in: path, required: true, schema: {type: string, format: uuid}}
        - {name: identity_id, in: path, required: true, schema: {type: string, format: uuid}}
      responses:
        "204": {description: Сопоставление снято, пара свободна}
        "403": {description: "issuer_not_allowed | self_link_forbidden | …guard"}
        "404": {description: external_identity_not_found}
        "422": {description: "connection_identity_required | issuer_tenant_mismatch"}

components:
  securitySchemes:
    bootstrapToken: {type: apiKey, in: header, name: X-IAM-Bootstrap-Token}
    iamBearer:
      type: http
      scheme: bearer
      bearerFormat: JWT
      description: >
        Access token IAM audience `iam`. `iam:people` — человек, federation,
        член `people-admins` (ADR-0002). `iam:identities.link` — только
        `principal_type = agent`, token обмена PAT, только issuer
        `connection:<tenant token>:` (ADR-0004).
  schemas:
    ConnectionIssuer:
      type: string
      pattern: "^connection:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[a-z0-9._-]{1,200}$"
      example: "connection:3f6c2b1e-9d4a-4c1e-8f7b-2a5d6e7f8a90:crm-main"
    ExternalIdentityCreate:
      type: object
      required: [issuer, subject]
      properties:
        issuer:
          type: string
          minLength: 1
          maxLength: 500
          description: Префикс `connection:` — `ConnectionIssuer`, source `connection`.
        subject:
          type: string
          minLength: 1
          maxLength: 500
          description: Для `connection` — id пользователя во внешней системе.
    ExternalIdentityView:
      type: object
      required: [id, principal_id, issuer, subject, status, created_at]
      properties:
        id: {type: string, format: uuid}
        principal_id: {type: string, format: uuid}
        issuer: {type: string}
        subject: {type: string}
        status: {type: string, enum: [active, disabled]}
        created_at: {type: string, format: date-time}
    ExternalIdentityItem:
      type: object
      required: [id, principal_id, issuer, subject, status]
      properties:
        id: {type: string, format: uuid}
        principal_id: {type: string, format: uuid}
        issuer: {type: string}
        subject: {type: string}
        status: {type: string, enum: [active, disabled]}
    ExternalIdentityPage:
      type: object
      required: [items]
      properties:
        items:
          type: array
          items: {$ref: "#/components/schemas/ExternalIdentityItem"}
        next_after:
          type: [string, "null"]
          format: uuid
          description: Добавлено ADR-0004; с `subject` всегда null.
    PrincipalView:
      type: object
      required: [id, kind, display_name, status, created_at]
      properties:
        id: {type: string, format: uuid}
        kind: {type: string, enum: [human, agent, service_account, workload]}
        display_name: {type: string}
        status: {type: string}
        owner_principal_id: {type: [string, "null"], format: uuid}
        created_at: {type: string, format: date-time}
    PrincipalByEmailPage:
      type: object
      required: [items]
      properties:
        items:
          type: array
          description: Только `kind = human`, `status = active`; ноль, один или несколько.
          items: {$ref: "#/components/schemas/PrincipalView"}
```

События outbox (конверт `GET /api/v1/events` прежний):

```yaml
external_identity.linked:      # добавлены source и issuer во всех источниках (п. 4.1)
  payload:
    externalIdentityId: uuid
    principalId: uuid
    source: {enum: [manual, connection, federated, provisioned]}
    issuer: string
    identityProvider: string    # прежнее поле, только source = federated
external_identity.unlinked:    # новое, только source = connection
  payload: {externalIdentityId: uuid, principalId: uuid, source: connection, issuer: string}
```

## Последствия

- **Контракт token не меняется**: те же claims и тот же обмен PAT,
  `platform-auth-sdk` отличий не видит, contract-тест сверх существующих не
  нужен. Почта не попадает ни в token, ни в ответы чтения identity.
- **Миграция** (I014 и I015 — одна цепочка alembic, одна голова): колонка
  `email` с индексом, `source` += `connection`, проверка зарезервированного
  префикса у существующих провайдеров. Материал секретов в миграцию не
  попадает.
- **Развёртыванию** (суперпроект, `deploy/bootstrap.py`, задача выкатки):
  добавить `iam:identities.link` в allowed scopes audience `iam` и в потолок
  service account `fleet-controller`; агенту-коннектору — объявить scope в
  `identity.iam.scopeCeiling` и audience `iam` в ревизии (пакет провайдера,
  I028).
- **Периметр** (там же). Снаружи сейчас закрыт `/iam/api/v1/tenants/*`, кроме
  `federation:*`, а агенты fleet ходят в IAM по публичному адресу. Коннектору
  на периметре нужно открыть ровно:
  - `GET /iam/api/v1/tenants/*/principals:by-email`;
  - `GET /iam/api/v1/tenants/*/external-identities`;
  - `POST` и `DELETE /iam/api/v1/tenants/*/principals/*/external-identities`
    (и `…/{id}`) — привязка и снятие (п. 4.1–4.2).
  Все они защищены Bearer и guard'ом п. 5 (и `iam:people`/bootstrap), так что
  открытие не расширяет круг допущенных. Прочие маршруты людей
  (`POST/GET …/principals`, `:disable`, `:enable`,
  `GET …/principals/{p}/external-identities`) остаются закрытыми, как и
  маршруты identity provider'ов и аудиторий. Там же — фильтр параметра
  `email` в логе периметра (п. 2).
- **Несовместимость с CP-ADR-0073, требует правки в control-plane.** Ядро
  проверяет `scopeCeiling` шаблоном `^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$`
  (`AgentIamSpec`, `api/v1/schemas.py`), а в `iam:identities.link` есть точка:
  ревизия с этим scope сейчас получит `400`. IAM ограничений на имя scope не
  накладывает, `platform-auth-sdk` читает scope как строки. Имя оставлено
  как в plan §3; control-plane нужно расширить шаблон действия до
  `[a-z][a-z0-9.-]*` (только добавление: прежние значения остаются
  валидными) — в амендменте CP-ADR-0073 в составе I001 или отдельной задачей
  до I028. Альтернатива — переименовать scope в `iam:identities-link` здесь
  и в plan — отвергнута, пока владелец не решит иначе: план уже одобрен, а
  правка ядра — одна строка.
- **Консоль** (I030) сопоставляет вручную по `iam:people`: поиск по почте,
  список по issuer, привязка и снятие. Себя администратор не сопоставляет —
  это делает коннектор по почте или другой администратор.
- **Отзыв подключения в ядре IAM не видит**: сопоставления остаются, пока их
  не снимет коннектор или консоль (`DELETE`, список по issuer). Они входа не
  дают, а коннектор отозванного подключения не работает; очистку при
  `connection.revoked` решает владелец потока подключений.
- **Персональные данные.** Почта хранится только у identity провайдера
  (`federated` или `provisioned`), только записанная входом и только
  подтверждённая, не отдаётся чтением, не попадает в audit и события;
  поиск отвечает людьми, а не адресами. Адрес поиска идёт в query string:
  из access log IAM и лога периметра он вырезается (п. 2), остаточный риск
  (промежуточные узлы TLS, трассировка) принят явно. Subject identity подключения — идентификатор
  во внешней системе, как Telegram id у каналов (ADR-0002, п. 11).

## Отвергнутые варианты

- **Амендмент ADR-0002 вместо отдельного ADR** — ADR-0002 про людей,
  которыми управляет человек-администратор; агент-держатель, свой guard и
  новый источник identity переписали бы его п. 2–6.
- **Почта у Principal** — у Principal нет источника истины для почты: почта
  подтверждается конкретным IdP и принадлежит входу через него. Колонка у
  Principal требовала бы правил слияния из нескольких IdP и SCIM.
- **Поиск `POST …/principals:search` с адресом в теле** — адрес не попал бы
  в URI и журналы запросов без фильтров. Отвергнут: форма `GET ?email=`
  задана plan §3 и уже заложена в коннектор и консоль; фильтр access log и
  лога периметра (п. 2) закрывает тот же риск без смены контракта. Если
  владелец решит иначе — меняется только этот маршрут.
- **Почта из SCIM** — значение кадровой системы не подтверждено token IdP;
  совпадение по нему привязывало бы пользователя внешней системы к человеку,
  который этим ящиком не владеет.
- **Чтение Keycloak Admin API коннектором** (plan Р8) — связь интеграции с IdP
  в обход IAM (ст. III).
- **`iam:identities.link` в реестре привилегированных scope** — привилегированные
  scope не приносит PAT (ADR-0003, п. 5), а агент получает token только
  обменом PAT: scope стал бы недостижим для единственного держателя. Защиту
  даёт guard «только агент» и префикс issuer.
- **Выдать коннектору `iam:people`** — authority администратора людей
  (создание, отключение, чтение всех identity) ради сопоставления одного
  подключения; к тому же `iam:people` — только человеку из federation.
- **Отключение вместо удаления** при снятии сопоставления — отключённая
  identity продолжала бы занимать пару `(issuer, subject)`, и пересопоставить
  пользователя внешней системы другому человеку было бы нельзя.
- **Issuer в пространстве `iam:`** (как `iam:channel:…`) — форма
  `connection:<tenant>:<key>` задана plan Р9; резерв префикса у
  identity provider даёт ту же защиту от совпадения с issuer IdP.
