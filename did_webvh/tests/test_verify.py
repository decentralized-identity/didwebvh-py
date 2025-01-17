from datetime import datetime, timezone

import pytest

from did_webvh.askar import AskarSigningKey
from did_webvh.core.state import DocumentState, HashInfo
from did_webvh.verify import (
    _check_document_id_format,
    verify_proofs,
)


@pytest.fixture()
def mock_document() -> dict:
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
            "https://identity.foundation/.well-known/did-configuration/v1",
            "https://identity.foundation/linked-vp/contexts/v1",
        ],
        "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000",
        "authentication": [
            "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
        ],
        "service": [
            {
                "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain",
                "type": "LinkedDomains",
                "serviceEndpoint": "https://example.com%3A5000",
            },
            {
                "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#whois",
                "type": "LinkedVerifiablePresentation",
                "serviceEndpoint": "https://example.com%3A5000/.well-known/whois.vc",
            },
        ],
        "verificationMethod": [
            {
                "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs",
                "controller": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000",
                "type": "Multikey",
                "publicKeyMultibase": "z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs",
            }
        ],
        "assertionMethod": [
            "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
        ],
    }


@pytest.fixture()
def mock_document_state(mock_sk, mock_next_sk) -> DocumentState:
    pk1 = mock_sk.multikey
    pk2 = mock_next_sk.multikey
    next_pk = HashInfo.from_name("sha2-256").formatted_hash(pk2.encode("utf-8"))
    return DocumentState(
        params={
            "updateKeys": [pk1],
            "nextKeyHashes": [next_pk],
            "method": "did:tdw:0.4",
            "scid": "QmapF3WxwoFFugMjrnx2iCwfTWuFwxHEBouPmX9fm9jEN3",
        },
        params_update={
            "updateKeys": [pk1],
            "nextKeyHashes": [next_pk],
            "method": "did:tdw:0.4",
            "scid": "QmapF3WxwoFFugMjrnx2iCwfTWuFwxHEBouPmX9fm9jEN3",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:QmapF3WxwoFFugMjrnx2iCwfTWuFwxHEBouPmX9fm9jEN3:domain.example",
        },
        timestamp=datetime(2024, 9, 17, 17, 29, 32, 0, tzinfo=timezone.utc),
        timestamp_raw="2024-09-11T17:29:32Z",
        version_id="1-QmXXb2mW7hZVLM5PPjm5iKCYS2PHQnoLePLK1d172ABrDZ",
        version_number=1,
        last_version_id="QmapF3WxwoFFugMjrnx2iCwfTWuFwxHEBouPmX9fm9jEN3",
        proofs=[
            {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:key:z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun#z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun",
                "created": "2024-12-11T21:49:26Z",
                "proofPurpose": "authentication",
                "proofValue": "z3bAmyurHc7S5junyQ3s92HSMVn1bQUqLfmaoMCuyArDM9TtFaPEPB69bBApxXFZcg6nWnZCb2EtKrg24trXbqh2A",
            }
        ],
    )


@pytest.fixture()
def mock_sk() -> AskarSigningKey:
    return AskarSigningKey.from_jwk(
        '{"crv":"Ed25519","kty":"OKP","x":"iWIGdqmPSeg8Ov89VzUrKuLD7pJ8_askEwJGE1R5Zqk","d":"RJDq2-dY85mW1bbDMcrXPObeL-Ud-b8MrPO-iqxajv0"}'
    )


@pytest.fixture()
def mock_next_sk() -> AskarSigningKey:
    return AskarSigningKey.from_jwk(
        '{"crv":"Ed25519","kty":"OKP","x":"xeHpv1RMsUQUYQ74BFTcVTifqFjbkn-pjK9InsVt8EU","d":"uHFsgrJ9xQ8npyB5pNwjPdn7xABkGKYmXD2ZV5spz6I"}'
    )


VALID_DID = [
    "did:webvh:0000000000000000000000000000:mydomain.com",
    "did:webvh:0000000000000000000000000000:mydomain.com%3A500",
    "did:webvh:0000000000000000000000000000:mydomain.com%3A500:path",
    "did:webvh:0000000000000000000000000000:mydomain.com%3A500:path:extra",
    "did:webvh:0000000000000000000000000000:mydomain.com:path:extra",
]


@pytest.mark.parametrize("did", VALID_DID)
def test_valid_document_id(did: str):
    _check_document_id_format(did, "0000000000000000000000000000")


INVALID_DID = [
    # missing did:
    "DID:webvh:0000000000000000000000000000.mydomain.com",
    # invalid method
    "did:other:0000000000000000000000000000.mydomain.com",
    # missing scid
    "did:webvh:domain.example",
    "did:webvh:domain.example:path",
    # missing tld
    "did:webvh:0000000000000000000000000000",
    # missing domain
    "did:webvh:0000000000000000000000000000.com",
    "did:webvh:mydomain.0000000000000000000000000000",
    "did:webvh:mydomain.com.0000000000000000000000000000",
    # duplicate
    "did:webvh:0000000000000000000000000000.mydomain.com:path:0000000000000000000000000000",
]


@pytest.mark.parametrize("did", INVALID_DID)
def test_invalid_document_id(did: str):
    with pytest.raises(ValueError):
        _check_document_id_format(did, "0000000000000000000000000000")


def test_check_document_id_format():
    _check_document_id_format(
        "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com",
        "QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4",
    )
    # scid doesn't match
    with pytest.raises(ValueError):
        _check_document_id_format(
            "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGY:example.com",
            "QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4",
        )
    # wrong did method (web)
    with pytest.raises(ValueError):
        _check_document_id_format(
            "did:web:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com",
            "QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4",
        )
    # no path
    with pytest.raises(ValueError):
        _check_document_id_format(
            "did:web:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4",
            "QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4",
        )


def test_verify_proofs(mock_document_state, mock_next_sk):
    verify_proofs(mock_document_state, None, is_final=False)

    pk2 = mock_next_sk.multikey
    prev_state = mock_document_state
    current_state = DocumentState(
        params={
            "updateKeys": [pk2],
            "nextKeyHashes": [],
            "method": "did:tdw:0.4",
            "scid": "QmapF3WxwoFFugMjrnx2iCwfTWuFwxHEBouPmX9fm9jEN3",
        },
        params_update={
            "updateKeys": [pk2],
            "nextKeyHashes": [],
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:QmapF3WxwoFFugMjrnx2iCwfTWuFwxHEBouPmX9fm9jEN3:domain.example",
        },
        timestamp=datetime(2024, 9, 11, 17, 29, 33, 0, tzinfo=timezone.utc),
        timestamp_raw="2024-09-11T17:29:33Z",
        version_id="2-QmdmMJ9BevLMnj6ua7CurAN4wa3RDRrCTgzLWGZPyfpfTV",
        version_number=2,
        last_version_id="1-QmXXb2mW7hZVLM5PPjm5iKCYS2PHQnoLePLK1d172ABrDZ",
        proofs=[
            {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:key:z6MksmiAGYB2k2DWnRBeK5qooVKhaRZGXi89PFpKLPboJyor#z6MksmiAGYB2k2DWnRBeK5qooVKhaRZGXi89PFpKLPboJyor",
                "created": "2024-12-11T21:51:46Z",
                "proofPurpose": "authentication",
                "proofValue": "z3XmLPS6ZQ8P7fHydwJN7rR1HG2pvFL5Lb3QA2i4fLUN9gGZkHTcGXXL6oa1GNiLbT5u64murxhhCXB96dhZTPz9a",
            }
        ],
    )

    verify_proofs(state=current_state, prev_state=prev_state, is_final=False)

    # Bad proof for current state
    current_state.proofs = [
        {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": "did:key:z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun#z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun",
            "created": "2024-09-11T17:29:33Z",
            "proofPurpose": "authentication",
            "proofValue": "zbsr8px8V9vLvGMeM9znFJqoRmYeRNLAdn5wJ26XmnBMzSS5bb6Us2JG8TKjtooy3ofdRwaWvY4jb6TCVSyhzapZ",  # this is changed
        }
    ]
    with pytest.raises(ValueError):
        verify_proofs(state=current_state, prev_state=prev_state, is_final=False)
