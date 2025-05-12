"""High-level document state verification."""

from collections.abc import Awaitable

from .const import METHOD_NAME, METHOD_VERSION
from .core.did_url import DIDUrl
from .core.problem_details import ProblemDetails
from .core.resolver import HistoryVerifier
from .core.state import DocumentState, InvalidDocumentState
from .domain_path import DomainPath


class WebvhVerifier(HistoryVerifier):
    """`HistoryVerifier` for the webvh method."""

    def __init__(self, verify_proofs: bool = True):
        """Constructor."""
        self._verify_proofs = verify_proofs

    def verify_state(
        self, state: DocumentState, prev_state: DocumentState | None, is_final: bool
    ) -> Awaitable[None] | None:
        """Verify a new document state."""
        _check_document_id_format(state.document_id, state.params["scid"])
        _verify_params(state, prev_state)
        return super().verify_state(state, prev_state, is_final)


def _check_document_id_format(doc_id: str, scid: str):
    try:
        try:
            url = DIDUrl.decode(doc_id)
        except ValueError:
            raise ValueError("Could not parse document ID as DID URL") from None
        if url.root != url:
            raise ValueError("Document ID must not have a path or query components")
        if url.method != METHOD_NAME:
            raise ValueError(
                f"Document ID uses incorrect DID method, expected '{METHOD_NAME}'"
            )
        # may raise ValueError
        pathinfo = DomainPath.parse_identifier(url.identifier)
        if pathinfo.scid != scid:
            raise ValueError("SCID must be the first component of the method-specific ID")
    except ValueError as err:
        raise InvalidDocumentState(
            ProblemDetails.invalid_document(f"Invalid document ID: {err}", found=doc_id)
        ) from None


def _verify_params(state: DocumentState, prev_state: DocumentState):
    """Verify the correct parameters on a document state."""
    method = state.params.get("method")
    if method != f"did:{METHOD_NAME}:{METHOD_VERSION}":
        raise InvalidDocumentState(
            ProblemDetails.invalid_log_entry(
                f"Unexpected value for method parameter: {method}"
            )
        )
