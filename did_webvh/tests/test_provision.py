from tempfile import TemporaryDirectory

import pytest

from did_webvh.askar import AskarSigningKey
from did_webvh.provision import (
    auto_provision_did,
    encode_verification_method,
    genesis_document,
)

TEST_DID = "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com"


def test_encode_verification_method_absolute_kid():
    key = AskarSigningKey.generate("ed25519")
    key.kid = f"{TEST_DID}#key-01"
    vm = encode_verification_method(key)
    assert vm["id"] == f"{TEST_DID}#key-01"
    assert vm["controller"] == TEST_DID


def test_encode_verification_method_relative_kid():
    key = AskarSigningKey.generate("ed25519")
    key.kid = "#key-01"
    vm = encode_verification_method(key, TEST_DID)
    assert vm["id"] == f"{TEST_DID}#key-01"
    assert vm["controller"] == TEST_DID


def test_encode_verification_method_generated_kid():
    key = AskarSigningKey.generate("ed25519")
    key.kid = None
    vm = encode_verification_method(key, TEST_DID)
    assert vm["id"].startswith(f"{TEST_DID}#")
    assert vm["controller"] == TEST_DID


def test_encode_verification_method_requires_controller():
    key = AskarSigningKey.generate("ed25519")
    key.kid = "#key-01"
    with pytest.raises(ValueError):
        encode_verification_method(key)


def test_genesis_document_is_self_controlled():
    doc = genesis_document(TEST_DID)
    assert doc["id"] == TEST_DID
    assert doc["controller"] == TEST_DID


async def test_provisioned_document_is_self_controlled():
    with TemporaryDirectory("didwebvh") as tempdir:
        (_doc_dir, state, _key) = await auto_provision_did(
            "domain.example", "ed25519", "passkey", target_dir=tempdir
        )
    assert state.document["controller"] == state.document_id
