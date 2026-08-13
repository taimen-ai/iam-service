"""Ошибки SCIM в формате RFC 7644 §3.12.

SCIM-клиент (IGA, HR-система) не умеет читать `{"detail": ...}` FastAPI, поэтому
любой отказ на `/scim/v2` отдаётся документом `urn:ietf:params:scim:api:messages:2.0:Error`.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_CONTENT_TYPE = "application/scim+json"


class ScimFault(Exception):
    """Отказ SCIM с необязательным `scimType` из RFC 7644 таблицы 9."""

    def __init__(self, status_code: int, detail: str, *, scim_type: str | None = None) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.scim_type = scim_type

    def response(self) -> JSONResponse:
        payload: dict[str, Any] = {"schemas": [ERROR_SCHEMA], "status": str(self.status_code)}
        if self.scim_type is not None:
            payload["scimType"] = self.scim_type
        payload["detail"] = self.detail
        return JSONResponse(
            payload, status_code=self.status_code, media_type=SCIM_CONTENT_TYPE
        )


class ScimRoute(APIRoute):
    """Route, переводящий отказы в SCIM-формат.

    Валидация тела FastAPI тоже перехватывается: клиент должен получать
    `invalidValue`, а не 422 с внутренней структурой ошибок pydantic.
    """

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                return await original(request)
            except ScimFault as fault:
                return fault.response()
            except RequestValidationError as exc:
                return ScimFault(
                    400, f"request does not match the SCIM schema: {exc.errors()[0]['loc']}",
                    scim_type="invalidValue",
                ).response()

        return handler
