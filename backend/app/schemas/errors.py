from pydantic import BaseModel


class ErrorDetail(BaseModel):
    """One validation problem. Submitted values are intentionally never echoed back."""

    location: str
    message: str


class ErrorBody(BaseModel):
    code: str
    message: str
    details: list[ErrorDetail] | None = None


class ErrorResponse(BaseModel):
    """Standard error envelope used by every non-2xx API response."""

    error: ErrorBody
