import pytest

from did_webvh.verify import _check_document_id_format

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
