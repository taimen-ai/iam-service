# Reference deployment upstream IdP

Воспроизводимое окружение для проверки OIDC и LDAP federation в `iam-service`:
Keycloak как reference Identity Provider и OpenLDAP как test fixture каталога.
Это deployment adapter, а не зависимость сервиса: IAM работает со стандартными
OIDC discovery, JWKS и claims, а не с внутренними API Keycloak.

## Что поднимается

| Сервис | Роль |
|---|---|
| `openldap` | каталог-фикстура: одна OU пользователей, одна OU групп, один пользователь, одна группа |
| `ldap-seed` | одноразовая загрузка структуры каталога и установка пароля пользователя из окружения |
| `realm-render` | подстановка connection и bind credential в шаблон realm перед импортом |
| `keycloak` | realm `platform`, clients, protocol mappers и LDAP User Federation в режиме `READ_ONLY` |

Realm содержит три клиента:

- `iam-service` — audience, который `iam-service` ожидает в upstream token;
- `platform-cli` — public client для browser и device flow; пароль каталога не
  принимает (`directAccessGrants` выключен);
- `local-verification` — **только для локальной проверки развёртывания**:
  включённый direct access grant позволяет получить token по паролю каталога
  напрямую в Keycloak. В общих окружениях этот client отключают.

## Секреты

Пароли и bind credential не хранятся ни в compose, ни в realm-шаблоне, ни в
LDIF. Запуск требует переменных окружения и падает, если они не заданы:

```bash
export LDAP_ADMIN_PASSWORD=...
export LDAP_TEST_USER_PASSWORD=...
export KEYCLOAK_ADMIN_PASSWORD=...
```

Realm импортируется из `realm-template/platform-realm.json`, где на месте
connection, DN и bind credential стоят плейсхолдеры `__LDAP_*__`. Их
подставляет сервис `realm-render` в отдельный volume: realm-import Keycloak не
разворачивает переменные окружения самостоятельно.

## Запуск

```bash
docker compose -f deploy/keycloak/docker-compose.yml up -d
```

Готовность realm:

```bash
curl -sf http://localhost:8081/realms/platform/.well-known/openid-configuration
```

Остановка вместе с данными каталога:

```bash
docker compose -f deploy/keycloak/docker-compose.yml down -v
```

## Что проверяет federation

Токен пользователя из LDAP содержит стабильный `ldap_id` (LDAP `entryUUID`),
`groups` без полного пути и `acr`. IAM связывает Principal по `issuer + subject`,
сверяет стабильный external ID, проецирует только allowlisted группы и не
выдаёт ни лицензию, ни service-local роль.

Интеграционный тест запускается против поднятого стенда:

```bash
IAM_TEST_OIDC_ISSUER=http://localhost:8081/realms/platform \
IAM_TEST_DIRECTORY_PASSWORD="$LDAP_TEST_USER_PASSWORD" \
  uv run pytest -m integration
```

Без этих переменных тест пропускается, поэтому обычный прогон остаётся
автономным.

## Границы

- LDAP подключается только к Keycloak; `iam-service` и resource services не
  ходят в каталог и не принимают пароль каталога.
- `editMode: READ_ONLY` означает, что lifecycle пользователей остаётся в
  каталоге: Keycloak и IAM его не изменяют.
- Keycloak Groups не являются авторитетным RBAC продукта: они проецируются в
  IAM Groups только по явному allowlist, а доменные разрешения остаются за
  resource service.
