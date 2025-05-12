import json
from copy import deepcopy

import pytest

from did_webvh.core.file_utils import AsyncTextGenerator, AsyncTextReadError, read_str
from did_webvh.core.resolver import (
    DereferencingResult,
    DidResolver,
    HistoryResolver,
    HistoryVerifier,
    ResolutionResult,
    dereference_fragment,
    normalize_services,
    reference_map,
)


class MockHistoryResolver(HistoryResolver):
    def __init__(
        self,
        entry_log: str,
        witness_log: str | None = None,
    ):
        """Constructor."""
        self.entry_log = entry_log
        self.witness_log = witness_log

    def resolve_entry_log(self, _document_id: str) -> AsyncTextGenerator:
        """Resolve the entry log file for a DID."""
        return read_str(self.entry_log)

    def resolve_witness_log(self, _document_id: str) -> AsyncTextGenerator:
        """Resolve the witness log file for a DID."""
        return read_str(self.witness_log or "")


class MockHistoryVerifier(HistoryVerifier):
    def __init__(self):
        super().__init__(verify_proofs=False)


mock_document = {
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1",
        "https://identity.foundation/.well-known/did-configuration/v1",
        "https://identity.foundation/linked-vp/contexts/v1",
    ],
    "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000",
    "authentication": [
        "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
    ],
    "service": [
        {
            "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain",
            "type": "LinkedDomains",
            "serviceEndpoint": "https://example.com%3A5000",
        },
        {
            "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#whois",
            "type": "LinkedVerifiablePresentation",
            "serviceEndpoint": "https://example.com%3A5000/whois.vp",
        },
    ],
    "verificationMethod": [
        {
            "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs",
            "controller": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000",
            "type": "Multikey",
            "publicKeyMultibase": "z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs",
        }
    ],
    "assertionMethod": [
        "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
    ],
}

# async def test_generate_history():
#     from did_webvh.core.state import DocumentState

#     state1 = DocumentState.initial({"method": "testmethod"}, '{"id": "docid-{SCID}"}')
#     state2 = state1.create_next(None)
#     history = [state1.history_line(), state2.history_line()]
#     print(history)


async def test_resolve_history():
    HISTORY = [
        {
            "versionId": "1-QmV2AdEkGSvn3K5v7x73rFVMrhVxAUbDdPRhx2fmVRFpdE",
            "versionTime": "2025-01-20T23:46:33Z",
            "parameters": {
                "method": "testmethod",
                "scid": "QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH",
            },
            "state": {"id": "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH"},
            "proof": [],
        },
        {
            "versionId": "2-QmaofgPQBFQBEX9dFjsYsJXTgmMhZoEXwfNegVZ38rQ7YX",
            "versionTime": "2025-01-20T23:46:33Z",
            "parameters": {},
            "state": {"id": "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH"},
            "proof": [],
        },
    ]
    history = MockHistoryResolver("\n".join(map(json.dumps, HISTORY)))
    resolver = DidResolver(MockHistoryVerifier())
    res = await resolver.resolve(
        "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH", history
    )
    assert isinstance(res, ResolutionResult)
    assert isinstance(res.document, dict)
    assert res.document_metadata["versionNumber"] == 2

    res = await resolver.resolve("bad-docid", history)
    assert res.document is None
    assert res.resolution_metadata["error"] == "invalidDid"
    assert res.resolution_metadata["problemDetails"]["type"].endswith(
        "#did-log-id-mismatch"
    )


async def test_resolve_history_failed_request():
    class BadResolver(HistoryResolver):
        def resolve_entry_log(self, _document_id: str) -> AsyncTextGenerator:
            """Resolve the entry log file for a DID."""
            raise AsyncTextReadError("read error")

    resolver = DidResolver(MockHistoryVerifier())
    res = await resolver.resolve("docid", BadResolver())
    assert isinstance(res, ResolutionResult)
    assert res.document is None
    assert res.resolution_metadata["error"] is not None


def test_reference_map():
    result = reference_map(mock_document)
    assert isinstance(result, dict)

    # Use dict instead of list
    services_in_dict_document = deepcopy(mock_document)
    services_in_dict_document["service"] = {
        "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain",
        "type": "LinkedDomains",
        "serviceEndpoint": "https://example.com%3A5000",
    }
    reference_map(services_in_dict_document)

    # id isn't a string
    bad_id_document = deepcopy(mock_document)
    bad_id_document["id"] = 123
    with pytest.raises(ValueError):
        reference_map(bad_id_document)


def test_normalize_services():
    result = normalize_services(mock_document)
    assert isinstance(result, list)

    # Service isn't a dict
    bad_service_document = deepcopy(mock_document)
    bad_service_document["service"] = [
        '{"id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain","type": "LinkedDomains","serviceEndpoint": "https://example.com%3A5000"}'
    ]

    with pytest.raises(ValueError):
        normalize_services(bad_service_document)

    # Service doesn't contain # symbol
    no_hash_symbol_document = deepcopy(mock_document)
    no_hash_symbol_document["service"] = [
        {
            "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain",
            "type": "LinkedDomains",
            "serviceEndpoint": "https://example.com%3A5000",
        },
        {
            "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000",
            "type": "LinkedVerifiablePresentation",
            "serviceEndpoint": "https://example.com%3A5000/whois.vp",
        },
    ]

    with pytest.raises(ValueError):
        normalize_services(no_hash_symbol_document)

    # Services are in a dict instead of list
    services_in_dict_document = deepcopy(mock_document)
    services_in_dict_document["service"] = {
        "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain",
        "type": "LinkedDomains",
        "serviceEndpoint": "https://example.com%3A5000",
    }

    normalize_services(services_in_dict_document)


def test_dereference_fragment():
    result = dereference_fragment(
        mock_document, "#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
    )
    assert isinstance(result, DereferencingResult)
    result = dereference_fragment(mock_document, "#domain")
    assert isinstance(result, DereferencingResult)

    # This ref doesn't exist
    result = dereference_fragment(
        mock_document, "#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAz"
    )
    assert isinstance(result, DereferencingResult)
    assert result.dereferencing_metadata.get("error") is not None
