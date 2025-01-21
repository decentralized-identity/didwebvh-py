"""High-level document state verification."""

from asyncio import get_running_loop
from collections.abc import Awaitable

from .const import METHOD_NAME, METHOD_VERSION
from .core.did_url import DIDUrl
from .core.proof import resolve_did_key
from .core.resolver import HistoryVerifier
from .core.state import DocumentState
from .domain_path import DomainPath


def _check_document_id_format(doc_id: str, scid: str):
    url = DIDUrl.decode(doc_id)
    if url.root != url:
        raise ValueError("Document identifier must be a DID")
    if url.method != METHOD_NAME:
        raise ValueError(f"Expected DID method to be '{METHOD_NAME}'")
    pathinfo = DomainPath.parse_identifier(url.identifier)
    if pathinfo.scid != scid:
        raise ValueError("SCID must be the first component of the method-specific ID")


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

        if (
            self._verify_proofs
            and state.version_number == 1
            or state.is_authz_event
            or is_final
        ):
            return get_running_loop().run_in_executor(
                None, _verify_proofs, state, prev_state
            )


def _verify_params(state: DocumentState, prev_state: DocumentState):
    """Verify the correct parameters on a document state."""
    if (
        prev_state
        and prev_state.document_id != state.document_id
        and not prev_state.params.get("portable", False)
    ):
        raise ValueError("Document ID updated on non-portable DID")
    method = state.params.get("method")
    if method != f"did:{METHOD_NAME}:{METHOD_VERSION}":
        raise ValueError(f"Unexpected value for method parameter: {method}")


def _verify_proofs(state: DocumentState, prev_state: DocumentState):
    """Verify all proofs on a document state."""
    proofs = state.proofs
    if not proofs:
        raise ValueError("Missing history version proof(s)")
    if not prev_state or prev_state.next_key_hashes:
        update_keys = state.update_keys
    else:
        update_keys = prev_state.update_keys
    for proof in proofs:
        method_id = proof.get("verificationMethod")
        vmethod = resolve_did_key(method_id)
        if vmethod["publicKeyMultibase"] not in update_keys:
            raise ValueError(f"Update key not found: {method_id}")
        state.verify_proof(
            proof=proof,
            method=vmethod,
        )
