"""Support for DID resolution."""

import json
from asyncio import ensure_future, gather
from collections.abc import Awaitable
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from inspect import isawaitable
from pathlib import Path
from typing import Optional

# from multidict import MultiDict
from .date_utils import make_timestamp
from .file_utils import (
    AsyncTextGenerator,
    AsyncTextReadError,
    read_text_file,
)
from .state import DocumentMetadata, DocumentState
from .witness import CheckedWitness


class ResolutionError(Exception):
    """An error raised during DID resolution."""

    error: str
    message: Optional[str] = None

    def __init__(
        self,
        error: str,
        message: str = None,
        status_code: int = 400,
    ):
        """Initializer."""
        super().__init__()
        self.error = error
        self.message = message
        self.status_code = status_code

    def serialize(self) -> dict:
        """Serialize this error to a JSON-compatible dictionary."""
        return {
            "error": self.error,
            "errorMessage": self.message,
            "contentType": "application/did+ld+json",
        }


@dataclass
class ResolutionResult:
    """The result of a DID resolution operation."""

    document: Optional[dict] = None
    document_metadata: Optional[dict] = None
    resolution_metadata: Optional[dict] = None

    def serialize(self) -> dict:
        """Serialize this result to a JSON-compatible dictionary."""
        return {
            "@context": "https://w3id.org/did-resolution/v1",
            "didDocument": self.document,
            "didDocumentMetadata": self.document_metadata,
            "didResolutionMetadata": self.resolution_metadata,
        }


@dataclass
class DereferencingResult:
    """The result of a DID dereferencing operation."""

    dereferencing_metadata: dict
    content: str = ""
    content_metadata: Optional[dict] = None

    def serialize(self) -> dict:
        """Serialize this result to a JSON-compatible dictionary."""
        return {
            "@context": "https://w3id.org/did-resolution/v1",
            "dereferencingMetadata": self.dereferencing_metadata,
            "content": self.content,
            "contentMetadata": self.content_metadata or {},
        }


class HistoryResolver:
    """Generic history resolver base class."""

    def resolve_entry_log(self, document_id: str | None) -> AsyncTextGenerator:
        """Resolve the entry log file for a DID."""
        raise NotImplementedError()

    def resolve_witness_log(self, document_id: str | None) -> AsyncTextGenerator:
        """Resolve the witness log file for a DID."""
        raise NotImplementedError()


class LocalHistoryResolver(HistoryResolver):
    """A history resolver which loads local log files."""

    def __init__(
        self,
        entry_path: str | Path,
        witness_path: str | Path | None = None,
    ):
        """Constructor."""
        self.entry_path = Path(entry_path)
        self.witness_path = Path(witness_path) if witness_path else None

    def resolve_entry_log(self, _document_id: str | None) -> AsyncTextGenerator:
        """Resolve the entry log file for a DID."""
        return read_text_file(self.entry_path)

    def resolve_witness_log(self, _document_id: str | None) -> AsyncTextGenerator:
        """Resolve the witness log file for a DID."""
        if self.witness_path:
            return read_text_file(self.witness_path)
        raise AsyncTextReadError("Missing witness log path")


class HistoryVerifier:
    """Generic DID verifier class."""

    def verify_state(
        self, state: DocumentState, prev_state: DocumentState | None, final: bool
    ) -> Awaitable[None] | None:
        """Verify a new document state."""

    def verify_witness(self, witness: dict) -> Awaitable[CheckedWitness | None] | None:
        """Verify a document witness."""


class DidResolver:
    """Generic DID resolver class, which accepts a custom log resolver and verifier."""

    def __init__(self, verifier: HistoryVerifier):
        """Constructor."""
        self.verifier = verifier

    async def resolve(
        self,
        document_id: str,
        source: HistoryResolver,
        *,
        version_id: int | str | None = None,
        version_time: datetime | str | None = None,
    ) -> ResolutionResult:
        """Resolve a `ResolutionResult` from a document ID and history resolver.

        Params:
            document_id: the DID to be resolved
            source: the `HistoryResolver` instance to use
            version_id: stop parsing at the requested versionId
            version_time: stop parsing at the most recent entry before
                or exactly matching the requested versionTime
        """
        if isinstance(version_id, str):
            # FIXME handle conversion error
            version_id = int(str)
        if isinstance(version_time, str):
            # FIXME handle conversion error
            version_time = make_timestamp(version_time)[0]
        try:
            (state, doc_meta) = await self.resolve_state(
                document_id, source, version_id=version_id, version_time=version_time
            )
        except AsyncTextReadError as err:
            return ResolutionResult(
                resolution_metadata=ResolutionError(
                    "notFound", f"History resolution error: {str(err)}"
                ).serialize()
            )
        except ValueError as err:
            return ResolutionResult(
                resolution_metadata=ResolutionError("invalidDid", str(err)).serialize()
            )

        if state.document_id != document_id:
            res_result = ResolutionResult(
                resolution_metadata=ResolutionError(
                    "invalidDid", "Document @id mismatch"
                ).serialize()
            )
        else:
            res_result = ResolutionResult(
                document=state.document, document_metadata=doc_meta.serialize()
            )
        return res_result

    async def resolve_state(
        self,
        document_id: str | None,
        source: HistoryResolver,
        *,
        version_id: int | None = None,
        version_time: datetime | None = None,
    ) -> tuple[DocumentState, DocumentMetadata]:
        """Resolve a specific document state and document metadata."""
        created = None
        prev_state = None
        state = None
        next_state = None
        aborted_err = None
        found = None
        line_no = 0
        version_checks = []
        version_ids = []
        witness_checks = {}

        async with source.resolve_entry_log(document_id) as entry_log:
            while not aborted_err:
                prev_state = state
                state = next_state
                next_state = None

                try:
                    line = await anext(entry_log)
                    line_no += 1
                    try:
                        parts = json.loads(line)
                    except ValueError as e:
                        raise ValueError(
                            f"Invalid history JSON on line {line_no}: {e}"
                        ) from None

                    # may raise ValueError
                    next_state = DocumentState.load_history_line(parts, state)
                    next_state.check_version_id()
                except StopAsyncIteration:
                    pass
                except ValueError as e:
                    aborted_err = e
                    next_state = None

                if found:
                    # no extra verification needed
                    continue

                if not state:
                    if not next_state:
                        if aborted_err:
                            raise aborted_err
                        raise ValueError("Empty document history")
                    if version_time and next_state.timestamp > version_time:
                        raise ValueError(f"Cannot resolve versionTime: {version_time}")
                    continue

                if version_id:
                    if state.version_id == version_id:
                        if version_time and state.timestamp > version_time:
                            raise ValueError(
                                "Specified `versionId` not valid at specified"
                                " `versionTime`"
                            )
                        found = state
                elif version_time and (
                    (next_state and next_state.timestamp > version_time)
                    or (not next_state and not aborted_err)
                ):
                    if state.timestamp > version_time:
                        raise ValueError(
                            "Resolved version not valid at specified `versionTime`"
                        )
                    found = state

                try:
                    verify = self.verifier.verify_state(state, prev_state, bool(found))
                except ValueError as err:
                    verify = err
                if isawaitable(verify):
                    verify = ensure_future(_check_proof(verify, state.version_id))
                    version_checks.append(verify)
                version_ids.append(state.version_id)

                if (
                    witness_rule := state.witness_rule
                ) and witness_rule not in witness_checks:
                    witness_checks[witness_rule] = state.version_id

                if not created:
                    created = state.timestamp
                if not next_state:
                    break

        if not found:
            if version_id:
                raise ValueError(f"Cannot resolve `versionId`: {version_id}")
            found = state

        if version_checks:
            all_checks = gather(*version_checks)
            # FIXME check witnesses in parallel
            await all_checks

        # if witness_checks:
        #     witness_errors = []
        #     witness_verify = MultiDict()
        #     async with source.resolve_witness_log(document_id) as witness_log:
        #         witness_text = await witness_log.text()
        #         try:
        #             witness_data = json.loads(witness_text)
        #         except ValueError as e:
        #             raise ValueError(f"Invalid witness JSON: {e}") from None
        #         if not isinstance(witness_data, list):
        #             raise ValueError("Invalid witness JSON: expected list")
        #         for entry in witness_data:
        #             if isinstance(entry, dict):
        #                 try:
        #                     check = await self.verifier.verify_witness(entry)
        #                 except ValueError as err:
        #                     witness_errors.append(err)
        #                     continue
        #                 if check:
        #                     witness_verify.add(check.witness_id, check.version_id)
        #     # FIXME verify rules

        doc_meta = DocumentMetadata(
            created=created,
            updated=state.timestamp,
            deactivated=state.deactivated,
            version_id=state.version_id,
            version_number=state.version_number,
        )
        return state, doc_meta


def _add_ref(doc_id: str, node: dict, refmap: dict, all: set):
    reft = node.get("id")
    if not isinstance(reft, str):
        return
    if reft.startswith("#"):
        reft = doc_id + reft
    elif "#" not in reft:
        return
    if reft in all:
        raise ValueError(f"Duplicate reference: {reft}")
    all.add(reft)
    refmap[reft] = node


async def _check_proof(verify: Awaitable[None], version_id: str):
    try:
        await verify
    except ValueError as err:
        raise ValueError(f"Error verifying proof for versionId '{version_id}'") from err


def reference_map(document: dict) -> dict[str, dict]:
    """Collect identified fragments (#ids) in a DID Document."""
    # indexing top-level collections only
    doc_id = document.get("id")
    if not isinstance(doc_id, str):
        raise ValueError("Missing document id")
    all = set()
    res = {}
    for k, v in document.items():
        if k == "@context":
            continue
        if isinstance(v, dict):
            res[k] = {}
            _add_ref(doc_id, v, res[k], all)
        elif isinstance(v, list):
            res[k] = {}
            for vi in v:
                if isinstance(vi, dict):
                    _add_ref(doc_id, vi, res[k], all)
    return res


def normalize_services(document: dict) -> list[dict]:
    """Normalize a `service` block to a list of dicts."""
    svcs = document.get("service", [])
    if not isinstance(svcs, list):
        svcs = [svcs]
    for svc in svcs:
        if not isinstance(svc, dict):
            raise ValueError("Expected map or list of map entries for 'service' property")
        svc_id = svc.get("id")
        if not svc_id or not isinstance(svc_id, str) or "#" not in svc_id:
            raise ValueError(f"Invalid service entry id: {svc_id}")
    return svcs


def dereference_fragment(document: dict, reft: str) -> DereferencingResult:
    """Dereference a fragment identifier within a document."""
    res = None
    try:
        if not reft.startswith("#"):
            raise ValueError("Expected reference to begin with '#'")
        refts = reference_map(document)
        reft = document["id"] + reft
        for blk in refts.values():
            if reft in blk:
                res = deepcopy(blk[reft])
                break
    except ValueError as err:
        return DereferencingResult(
            dereferencing_metadata=ResolutionError("notFound", str(err)).serialize(),
        )
    if not res:
        return DereferencingResult(
            dereferencing_metadata=ResolutionError(
                "notFound", f"Reference not found: {reft}"
            ).serialize()
        )
    ctx = []
    doc_ctx = document.get("@context")
    if isinstance(doc_ctx, str):
        ctx.append(doc_ctx)
    elif isinstance(doc_ctx, list):
        ctx.extend(doc_ctx)
    node_ctx = res.get("@context")
    if isinstance(node_ctx, str):
        ctx.append(node_ctx)
    elif isinstance(node_ctx, list):
        ctx.extend(node_ctx)
    if ctx:
        res = {"@context": ctx, **res}
    return DereferencingResult(dereferencing_metadata={}, content=json.dumps(res))
