"""One error envelope for the whole API (see schemas.errors.ErrorResponse)."""

from collections.abc import Mapping

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.schemas.errors import ErrorBody, ErrorDetail, ErrorResponse

_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    422: "validation_error",
    503: "unavailable",
}


class ApiProblem(StarletteHTTPException):
    """An expected failure with a stable, machine-readable code (the UI branches on `code`)."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(status_code=status_code, detail=message)
        self.code = code


def error_response(
    status_code: int,
    code: str,
    message: str,
    *,
    details: list[ErrorDetail] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    body = ErrorResponse(error=ErrorBody(code=code, message=message, details=details))
    return JSONResponse(body.model_dump(mode="json"), status_code=status_code, headers=headers)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = (
            exc.code if isinstance(exc, ApiProblem) else _CODES.get(exc.status_code, "http_error")
        )
        return error_response(exc.status_code, code, str(exc.detail), headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        details = [
            ErrorDetail(location=".".join(str(part) for part in error["loc"]), message=error["msg"])
            for error in exc.errors()
        ]
        return error_response(422, "validation_error", "Request validation failed", details=details)
