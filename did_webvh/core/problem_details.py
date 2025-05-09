"""Support for IETF problem details."""

from dataclasses import dataclass
from typing import Any


@dataclass
class ProblemDetails:
    """RFC 9457 problem details instance."""

    type: str
    title: str | None = None
    detail: str | None = None
    status: int | None = None
    exts: dict[str, Any] | None = None

    DEFAULT_SPEC_URI = "https://didwebvh.info/main/resolution-errors/"

    @classmethod
    def invalid_did(cls, detail: str = None, **exts):
        """Instantiate a generic invalid DID error."""
        return cls(
            type="https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID",
            title="The resolved DID is invalid.",
            detail=detail,
            **exts,
        )

    @classmethod
    def invalid_log_entry(cls, detail: str = None, **exts):
        """Instantiate an invalid log entry error."""
        return cls(
            type="#invalid-log-entry",
            title="Encountered an invalid log entry",
            detail=detail,
            **exts,
        )

    @classmethod
    def invalid_parameter(cls, detail: str = None, **exts):
        """Instantiate an invalid log parameter error."""
        return cls(
            type="#invalid-parameter",
            title="Encountered an invalid log parameter",
            detail=detail,
            **exts,
        )

    @classmethod
    def invalid_resolution_parameter(cls, detail: str = None, **exts):
        """Instantiate an invalid resolution parameter error."""
        return cls(
            type="#invalid-resolution-parameter",
            title="Encountered an invalid resolution parameter",
            detail=detail,
            **exts,
        )

    def __init__(
        self,
        type: str,
        title: str | None = None,
        detail: str | None = None,
        status: int | None = None,
        **exts,
    ):
        """Initializer."""
        if type.startswith("#"):
            type = ProblemDetails.DEFAULT_SPEC_URI + type
        self.type = type
        self.title = title
        self.detail = detail
        self.status = status
        self.exts = exts

    def serialize(self) -> dict:
        """Serialize problem details to a JSON-compatible dictionary."""
        return {
            **{
                k: v
                for k, v in {
                    "type": self.type,
                    "status": self.status,
                    "title": self.title,
                    "detail": self.detail,
                }.items()
                if v is not None
            },
            **(self.exts or {}),
        }
