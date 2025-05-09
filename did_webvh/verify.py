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
        url = DIDUrl.decode(doc_id)
    except ValueError as err:
        raise InvalidDocumentState(
            ProblemDetails.invalid_did(str(err), found=doc_id)
        ) from None
    if url.root != url:
        raise InvalidDocumentState(
            ProblemDetails.invalid_did("Document identifier must be a DID", found=doc_id)
        )
    if url.method != METHOD_NAME:
        raise InvalidDocumentState(
            ProblemDetails.invalid_did(f"Expected DID method to be '{METHOD_NAME}'")
        )
    try:
        pathinfo = DomainPath.parse_identifier(url.identifier)
    except ValueError as err:
        raise InvalidDocumentState(
            ProblemDetails.invalid_did(str(err), found=doc_id)
        ) from None
    if pathinfo.scid != scid:
        raise InvalidDocumentState(
            ProblemDetails.invalid_did(
                "SCID must be the first component of the method-specific ID", found=doc_id
            )
        )


def _verify_params(state: DocumentState, prev_state: DocumentState):
    """Verify the correct parameters on a document state."""
    method = state.params.get("method")
    if method != f"did:{METHOD_NAME}:{METHOD_VERSION}":
        raise InvalidDocumentState(
            ProblemDetails.invalid_log_entry(
                f"Unexpected value for method parameter: {method}"
            )
        )
