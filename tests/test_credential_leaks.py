"""Хелпер проверки утечки секрета детерминирован (TASK-001151)."""

from __future__ import annotations

import json
import uuid

import pytest

from credential_leaks import (
    MIN_SIGNIFICANT_LENGTH,
    assert_no_credential_leak,
    credential_secret,
    leaked_fragments,
)
from iam_service.pat.material import generate_platform_access_token

RANDOM_TOKENS = 200


def journal_about(token: str) -> str:
    """Журнал, в котором есть всё публичное о токене, но нет секрета."""

    prefix = token.split("_")[2]
    events = [
        {
            "id": str(uuid.uuid4()),
            "type": event_type,
            "credentialPrefix": prefix,
            "display": f"iam_pat_{prefix}_…",
            "principalId": str(uuid.uuid4()),
        }
        for event_type in ("credential.issued", "credential.exchanged", "credential.revoked")
    ]
    # Шум из того же алфавита, что и секрет: короткие совпадения в нём
    # неизбежны и утечкой не считаются.
    events.append({"noise": generate_platform_access_token().full_token * 3})
    return json.dumps({"items": events})


def test_secret_is_taken_by_format_even_with_underscores() -> None:
    # Синтетический токен формата собран из частей: цельный литерал gitleaks принимает за секрет.
    token = "_".join(("iam", "pat", "0123456789ab", "abc_def_ghi_jkl_mno_pq_x"))

    assert credential_secret(token) == "abc_def_ghi_jkl_mno_pq_x"
    # Однобуквенный хвост после последнего `_` утечкой не считается.
    assert_no_credential_leak(token, json.dumps({"x": "x", "prefix": "0123456789ab"}))


@pytest.mark.parametrize("attempt", range(RANDOM_TOKENS))
def test_random_tokens_never_false_positive(attempt: int) -> None:
    token = generate_platform_access_token().full_token

    assert_no_credential_leak(token, journal_about(token))


def test_leak_of_a_significant_part_is_caught() -> None:
    token = generate_platform_access_token().full_token
    secret = credential_secret(token)
    middle = secret[5 : 5 + MIN_SIGNIFICANT_LENGTH]

    assert leaked_fragments(token, f"… {token} …") == [token]
    assert leaked_fragments(token, f"… {secret} …") == [secret]
    assert leaked_fragments(token, f"… {middle} …") == [middle]
    assert leaked_fragments(token, f"… {middle[:-1]} …") == []
    with pytest.raises(AssertionError):
        assert_no_credential_leak(token, f"tail={secret[-MIN_SIGNIFICANT_LENGTH:]}")
