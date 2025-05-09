"""Resolution of did:webvh DIDs."""

import argparse
import asyncio
import json
import urllib.parse
from datetime import datetime
from pathlib import Path

from .core.did_url import DIDUrl
from .core.file_utils import AsyncTextReadError, read_url
from .core.problem_details import ProblemDetails
from .core.resolver import (
    DereferencingResult,
    DidResolver,
    ResolutionError,
    ResolutionResult,
    dereference_fragment,
    normalize_services,
    reference_map,
)
from .history import did_base_url, did_history_resolver
from .verify import WebvhVerifier


def extend_document_services(document: dict, base_url: str):
    """Add the implicit services to a DID document, where not defined."""
    document["service"] = normalize_services(document)
    pos = base_url.rfind("/")
    if pos <= 0:
        raise ValueError(f"Invalid base URL: {base_url}")
    base_url = base_url[: pos + 1]
    ref_map = reference_map(document)
    doc_id = document["id"]

    if doc_id + "#files" not in ref_map["service"]:
        document["service"].append(
            {
                # FIXME will need to add @context if not provided already
                "id": doc_id + "#files",
                "type": "relativeRef",
                "serviceEndpoint": base_url,
            }
        )

    if doc_id + "#whois" not in ref_map["service"]:
        document["service"].append(
            {
                "@context": "https://identity.foundation/linked-vp/contexts/v1",
                "id": doc_id + "#whois",
                "type": "LinkedVerifiablePresentation",
                "serviceEndpoint": base_url + "whois.vp",
            }
        )


def _find_service(document: dict, name: str) -> dict | None:
    if name.startswith("#"):
        name = document["id"] + name
    ref_map = reference_map(document)
    return ref_map.get("service", {}).get(name)


async def resolve_did(
    did: DIDUrl | str,
    *,
    local_history: Path | None = None,
    version_id: str | None = None,
    version_number: int | str | None = None,
    version_time: datetime | str | None = None,
    add_implicit: bool = True,
) -> ResolutionResult:
    """Resolve a did:webvh DID or DID URL.

    Resolution parameters within a DID URL are not applied.
    """
    didurl = DIDUrl.decode(did) if isinstance(did, str) else did
    source = did_history_resolver(local_history=local_history)
    result = await DidResolver(WebvhVerifier()).resolve(
        didurl.did,
        source,
        version_id=version_id,
        version_number=version_number,
        version_time=version_time,
    )
    if result.document and add_implicit:
        extend_document_services(result.document, did_base_url(didurl, files=True))
    return result


def _resolve_relative_ref_to_url(document: dict, service: str, relative_ref: str) -> str:
    svc = _find_service(document, f"#{service}")
    if svc:
        endpt = svc.get("serviceEndpoint")
        if isinstance(endpt, str):
            return urllib.parse.urljoin(endpt, relative_ref.removeprefix("/"))


async def _resolve_relative_ref(
    document: dict, service: str, relative_ref: str
) -> DereferencingResult:
    url = _resolve_relative_ref_to_url(document, service, relative_ref)
    if not url:
        return DereferencingResult(
            dereferencing_metadata=ResolutionError.not_found(
                # "Unable to resolve relative path"
            ).serialize()
        )
    try:
        async with read_url(url) as req:
            content = await req.text()
            return DereferencingResult(
                content=content,
                # FIXME add content type
                content_metadata={},
                dereferencing_metadata={},
            )
    except AsyncTextReadError:
        return DereferencingResult(
            dereferencing_metadata=ResolutionError.not_found(
                # f"Error fetching relative path: {str(err)}"
            ).serialize()
        )


async def resolve(didurl: str, *, local_history: Path | None = None) -> dict:
    """Resolve a did:webvh DID URL, applying any included DID resolution parameters."""
    try:
        didurl = DIDUrl.decode(didurl)
    except ValueError as err:
        return ResolutionResult(
            resolution_metadata=ResolutionError.invalid_did(
                ProblemDetails.invalid_did(str(err))
            )
        ).serialize()

    query = didurl.query_dict
    relative_ref = query.get("relativeRef")
    service_name = query.get("service")
    version_id = query.get("versionId")
    version_number = query.get("versionNumber")
    version_time = query.get("versionTime")
    # FIXME reject unknown query parameters?

    if didurl.path:
        # if service_name or relative_ref: invalid?
        service_name = "files"
        relative_ref = didurl.path

    result = await resolve_did(
        didurl.root,
        local_history=local_history,
        version_id=version_id,
        version_number=version_number,
        version_time=version_time,
    )

    if service_name and relative_ref and result.document:
        result = await _resolve_relative_ref(result.document, service_name, relative_ref)
    elif didurl.fragment and result.document:
        result = dereference_fragment(result.document, didurl.fragment)
    # FIXME relative_ref + fragment combination?

    return result.serialize()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="resolve a did:webvh DID URL")
    parser.add_argument("-f", "--file", help="the path to a local DID history file")
    parser.add_argument("didurl", help="the DID URL to resolve")
    args = parser.parse_args()

    result = asyncio.run(
        resolve(args.didurl, local_history=Path(args.file) if args.file else None)
    )

    print(json.dumps(result, indent=2))
