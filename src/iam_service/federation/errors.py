from __future__ import annotations


class FederationError(Exception):
    """Отказ federation с кодом, пригодным для API и audit.

    `code` не содержит upstream token, subject или другой sensitive payload:
    сообщение целиком уходит в ответ клиенту и в audit reason.
    """

    def __init__(self, code: str, *, status_code: int = 401) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code
