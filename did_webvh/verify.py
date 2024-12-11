"""High-level document state verification."""

from .const import METHOD_NAME, METHOD_VERSION
from .core.did_url import DIDUrl
from .core.proof import di_jcs_verify
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


def verify_proofs(state: DocumentState, prev_state: DocumentState, is_final: bool):
    """Verify all proofs on a document state."""
    doc_id = state.document_id
    proofs = state.proofs
    if not proofs:
        raise ValueError("Missing history version proof(s)")
    if not prev_state or prev_state.next_key_hashes:
        update_keys = state.update_keys
    else:
        update_keys = prev_state.update_keys
    for proof in proofs:
        method_id = proof.get("verificationMethod")
        if not isinstance(method_id, str):
            raise ValueError(f"Invalid proof verification method: {type(method_id)}")
        if "#" not in method_id:
            raise ValueError("Expected verification method reference with fragment")
        if method_id.startswith("#"):
            method_fragment = method_id[1:]
            method_id = doc_id + method_id
            method_ctl = doc_id
        else:
            fpos = method_id.find("#")
            method_ctl = method_id[:fpos]
            fpos = fpos + 1
            method_fragment = method_id[fpos:]
        if not method_ctl.startswith("did:key:"):
            raise ValueError(f"Unsupported verification method: {method_id}")
        method_key = method_ctl.removeprefix("did:key:")
        if method_key != method_fragment:
            raise ValueError(
                f"Verification method fragment does not match public key: {method_id}"
            )
        if method_key not in update_keys:
            raise ValueError(f"Cannot resolve verification method: {method_id}")
        vmethod = {"type": "Multikey", "publicKeyMultibase": method_key}
        di_jcs_verify(
            state=state,
            proof=proof,
            method=vmethod,
        )


def verify_params(state: DocumentState, prev_state: DocumentState, is_final: bool):
    """Verify the correct parameters on a document state."""
    _check_document_id_format(state.document_id, state.params["scid"])
    if (
        prev_state
        and prev_state.document_id != state.document_id
        and not prev_state.params.get("portable", False)
    ):
        raise ValueError("Document ID updated on non-portable DID")
    method = state.params.get("method")
    if method != f"did:{METHOD_NAME}:{METHOD_VERSION}":
        raise ValueError(f"Unexpected value for method parameter: {method}")


def verify_all(state: DocumentState, prev_state: DocumentState, is_final: bool):
    """Verify the proofs and parameters on a document state."""
    # FIXME add resolution context instead of is_final flag?
    verify_params(state, prev_state, is_final)
    if state.version_number == 1 or state.is_authz_event or is_final:
        verify_proofs(state, prev_state, is_final)
