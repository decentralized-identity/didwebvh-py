import json
from tempfile import TemporaryDirectory

import pytest

from did_webvh.const import DOCUMENT_FILENAME, HISTORY_FILENAME
from did_webvh.provision import auto_provision_did
from did_webvh.resolver import extend_document_services, reference_map, resolve
from did_webvh.update import auto_update_did


def test_extend_services():
    doc = {"id": "docid"}
    extend_document_services(doc, "http://domain.example/")
    assert "service" in doc
    ref_map = reference_map(doc)
    assert "service" in ref_map
    assert "docid#files" in ref_map["service"]
    assert "docid#whois" in ref_map["service"]


@pytest.mark.parametrize("domain_path", ("domain.example", "domain.example/path"))
@pytest.mark.parametrize("prerotation", (True, False))
async def test_provision_resolve_local(domain_path: str, prerotation: bool):
    pytest.importorskip("aries_askar")  # the provisioned keys are kept in Askar
    tempdir = TemporaryDirectory("didwebvh")
    (doc_dir, state, key) = await auto_provision_did(
        domain_path,
        "ed25519",
        "passkey",
        prerotation=prerotation,
        target_dir=tempdir.name,
    )
    res = await resolve(
        state.document_id, local_history=doc_dir.joinpath(HISTORY_FILENAME)
    )
    assert res.get("didDocument")
    assert res.get("didDocumentMetadata")
    # a string, defaulted when the parameter is not set
    assert res["didDocumentMetadata"]["ttl"] == "3600"


async def test_update_resolve_fragment():
    pytest.importorskip("aries_askar")  # the provisioned keys are kept in Askar
    tempdir = TemporaryDirectory("didwebvh")
    (doc_dir, state, _key) = await auto_provision_did(
        "domain.example",
        "ed25519",
        "passkey",
        target_dir=tempdir.name,
    )
    with open(doc_dir.joinpath(DOCUMENT_FILENAME), "w") as out:
        doc = state.document_copy()
        doc["service"] = [{"id": state.document_id + "#fragment", "type": "Test"}]
        json.dump(doc, out)
    state = await auto_update_did(doc_dir, "passkey")
    res = await resolve(
        state.document_id + "#fragment", local_history=doc_dir.joinpath(HISTORY_FILENAME)
    )
    assert not res.get("didDocument")
    assert res.get("content")


async def test_deactivated_did_returns_no_document():
    pytest.importorskip("aries_askar")  # the provisioned keys are kept in Askar
    tempdir = TemporaryDirectory("didwebvh")
    (doc_dir, state, _key) = await auto_provision_did(
        "domain.example",
        "ed25519",
        "passkey",
        target_dir=tempdir.name,
    )
    with open(doc_dir.joinpath(DOCUMENT_FILENAME), "w") as out:
        json.dump(state.document_copy(), out)
    state = await auto_update_did(doc_dir, "passkey", params_update={"deactivated": True})
    history = doc_dir.joinpath(HISTORY_FILENAME)

    # The latest version is deactivated: no DIDDoc, and the metadata says so.
    res = await resolve(state.document_id, local_history=history)
    assert "error" not in (res.get("didResolutionMetadata") or {})
    assert res.get("didDocument") is None
    assert res["didDocumentMetadata"]["deactivated"] is True
    assert res["didDocumentMetadata"]["versionNumber"] == 2

    # The version before the deactivation still resolves to its DIDDoc.
    res = await resolve(state.document_id + "?versionNumber=1", local_history=history)
    assert res.get("didDocument")
    assert res["didDocument"]["id"] == state.document_id
