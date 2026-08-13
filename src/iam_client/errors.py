"""Ошибки локального клиента с устойчивыми кодами.

Код важнее текста: по нему CLI выбирает exit code, а тесты проверяют
поведение, не завися от формулировок. Ни один текст ошибки не содержит
секрета — в сообщение попадают только prefix токена и несекретные
идентификаторы.
"""

from __future__ import annotations


class IamClientError(Exception):
    """Базовая ошибка клиента."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class BindingError(IamClientError):
    """Репозиторий не связан с IAM или binding-файл некорректен."""


class CredentialError(IamClientError):
    """Локальное хранилище секрета недоступно или небезопасно."""


class RemoteError(IamClientError):
    """IAM или resource service отказал либо недоступен."""

    def __init__(self, code: str, message: str, *, status_code: int | None = None) -> None:
        super().__init__(code, message)
        self.status_code = status_code
