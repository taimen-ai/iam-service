"""Проверка «секрет не утёк» для тестов.

Секретная часть выделяется по формату токена из кода выпуска
(``iam_service.pat.material``), а не разрезанием по последнему ``_``:
секрет — ``secrets.token_urlsafe`` и сам может содержать ``_``, и тогда
``rsplit("_", 1)`` даёт хвост в один–два символа, который случайно
встречается в любом JSON (TASK-001151).

Утечкой считается появление в тексте целого токена, целого секрета или
любого его фрагмента длиной не меньше ``MIN_SIGNIFICANT_LENGTH`` — такой
фрагмент случайно не совпадает (64^16 вариантов), а утечку обрезанного
секрета он ловит.
"""

from __future__ import annotations

from iam_service.pat.material import (
    KIND_LEGACY_CONTROL_PLANE_API_KEY,
    KIND_PLATFORM_ACCESS_TOKEN,
    LEGACY_TAG,
    PAT_TAG,
    parse_presented_credential,
)

MIN_SIGNIFICANT_LENGTH = 16

_TAG_BY_KIND = {
    KIND_PLATFORM_ACCESS_TOKEN: PAT_TAG,
    KIND_LEGACY_CONTROL_PLANE_API_KEY: LEGACY_TAG,
}


def credential_secret(token: str) -> str:
    """Секретная часть ``<tag>_<prefix>_<secret>`` без публичного префикса."""

    presented = parse_presented_credential(token)
    assert presented is not None, "токен не в формате выпуска PAT"
    head = f"{_TAG_BY_KIND[presented.kind]}_{presented.public_prefix}_"
    assert token.startswith(head)
    secret = token[len(head) :]
    assert len(secret) >= MIN_SIGNIFICANT_LENGTH, "секрет короче значимого фрагмента"
    return secret


def significant_fragments(secret: str) -> set[str]:
    """Все подстроки секрета длиной ``MIN_SIGNIFICANT_LENGTH``.

    Любая более длинная утечка содержит хотя бы одну из них.
    """

    size = MIN_SIGNIFICANT_LENGTH
    return {secret[start : start + size] for start in range(len(secret) - size + 1)}


def leaked_fragments(token: str, text: str) -> list[str]:
    """Значимые части токена, найденные в тексте (пусто — утечки нет)."""

    if token in text:
        return [token]
    secret = credential_secret(token)
    if secret in text:
        return [secret]
    return sorted(fragment for fragment in significant_fragments(secret) if fragment in text)


def assert_no_credential_leak(token: str, text: str) -> None:
    """Ни токен, ни секрет, ни его значимая часть не встречаются в тексте."""

    leaked = leaked_fragments(token, text)
    # Сам секрет в сообщение не кладём — только число совпадений.
    assert not leaked, f"в тексте найдено {len(leaked)} значимых фрагментов секрета"
