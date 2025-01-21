"""History file management."""

import json
from datetime import datetime
from pathlib import Path

from .const import HISTORY_FILENAME, METHOD_NAME, WITNESS_FILENAME
from .core.did_url import DIDUrl
from .core.file_utils import AsyncTextGenerator, read_url
from .core.resolver import DidResolver, HistoryResolver, LocalHistoryResolver
from .core.state import DocumentMetadata, DocumentState
from .core.types import SigningKey
from .domain_path import DomainPath
from .verify import WebvhVerifier


def did_base_url(didurl: DIDUrl) -> str:
    """Determine the URL of the DID history file from a did:webvh DID URL."""
    if didurl.method != METHOD_NAME:
        raise ValueError("Invalid DID")
    pathinfo = DomainPath.parse_identifier(didurl.identifier)
    host = pathinfo.domain_port
    path = pathinfo.path or (".well-known",)
    return "/".join((f"https://{host}", *path, ""))


class WebvhHistoryResolver(HistoryResolver):
    """Webvh history resolver."""

    def resolve_entry_log(self, document_id: str) -> AsyncTextGenerator:
        """Resolve the entry log file for a DID."""
        return read_url(did_base_url(document_id) + HISTORY_FILENAME)

    def resolve_witness_log(self, document_id: str) -> AsyncTextGenerator:
        """Resolve the witness log file for a DID."""
        return read_url(did_base_url(document_id) + WITNESS_FILENAME)


def write_document_state(
    doc_dir: Path,
    state: DocumentState,
):
    """Append a new document state to a history log file."""
    history_path = doc_dir.joinpath(HISTORY_FILENAME)
    if state.version_number > 1:
        mode = "a"
        if not history_path.exists():
            raise RuntimeError(f"History path does not exist: {history_path}")
    else:
        mode = "w"

    with history_path.open(mode) as out:
        print(
            json.dumps(state.history_line()),
            file=out,
        )


def did_history_resolver(
    *,
    local_history: Path | None = None,
) -> HistoryResolver:
    """Create a DID history resolver."""
    if local_history:
        if not local_history.is_file():
            raise ValueError(f"History path not found: {local_history}")
        witness_path = local_history.parent.joinpath(WITNESS_FILENAME)
        if not witness_path.is_file():
            witness_path = None
        return LocalHistoryResolver(local_history, witness_path)
    else:
        return WebvhHistoryResolver()


async def load_local_history(
    path: str | Path,
    *,
    verify_proofs: bool = True,
) -> tuple[DocumentState, DocumentMetadata]:
    """Load a history log file into a final document state and metadata."""
    source = did_history_resolver(local_history=path)
    verifier = WebvhVerifier(verify_proofs=verify_proofs)
    return await DidResolver(verifier).resolve_state(None, source)


def update_document_state(
    prev_state: DocumentState,
    update_key: SigningKey,
    document: dict | None = None,
    params_update: dict | None = None,
    timestamp: str | datetime | None = None,
) -> DocumentState:
    """Update a document state, including a new signed proof."""
    state = prev_state.create_next(
        document=document,
        params_update=params_update,
        timestamp=timestamp,
    )
    # FIXME ensure the signing key is present in updateKeys
    state.proofs.append(state.create_proof(update_key, timestamp=state.timestamp))
    return state
