from datetime import datetime, timezone

import pytest

from did_webvh.askar import AskarSigningKey
from did_webvh.core.state import DocumentState, HashInfo
from did_webvh.proof import di_jcs_sign, di_jcs_sign_raw, di_jcs_verify


@pytest.fixture()
def mock_document() -> dict:
    return {
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
                "serviceEndpoint": "https://example.com%3A5000/.well-known/whois.vc",
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


def test_jcs_sign_verify(mock_sk):
    mock_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:domain.example\n",
        },
    )
    method = {
        "type": "Multikey",
        "publicKeyMultibase": mock_sk.multikey,
    }
    proof = di_jcs_sign(mock_state, sk=mock_sk)
    di_jcs_verify(mock_state, proof, method)
    proof = di_jcs_sign(
        mock_state,
        sk=mock_sk,
        timestamp=datetime.now(),
    )
    di_jcs_verify(mock_state, proof, method)
    proof = di_jcs_sign(
        mock_state,
        sk=mock_sk,
        timestamp=datetime.now(),
        kid="kid",
    )
    di_jcs_verify(mock_state, proof, method)


def test_jcs_sign_raw(mock_document):
    result = di_jcs_sign_raw(
        mock_document,
        sk=AskarSigningKey.generate("ed25519"),
        purpose="authentication",
        challenge="challenge",
    )
    assert isinstance(result, dict)
    di_jcs_sign_raw(
        mock_document,
        sk=AskarSigningKey.generate("p256"),
        purpose="authentication",
        challenge="challenge",
    )
    di_jcs_sign_raw(
        mock_document,
        sk=AskarSigningKey.generate("p384"),
        purpose="authentication",
        challenge="challenge",
    )
    with pytest.raises(TypeError):
        di_jcs_sign_raw(
            mock_document,
            sk=AskarSigningKey.generate("bls12381g1g2"),
            purpose="authentication",
            challenge="challenge",
        )


def test_di_jcs_verify(mock_document_state, mock_sk, mock_next_sk):
    bad_proof = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": "did:key:z6MkosXkYcPjPhWcvWbSxW26Lr3GqYEmqJXWj1mspB76Kqx8#z6MkosXkYcPjPhWcvWbSxW26Lr3GqYEmqJXWj1mspB76Kqx8",
        "created": "2024-09-10T22:31:17Z",
        "proofPurpose": "authentication",
        "proofValue": "zhLxMHk6oaVmoJ2Xo4Hw8QQG9RP4eNPuDg4co7ExcCXbe5sRgomLjCgQ9vevLVPWGar79iAh4t697jJ9iMYFNQ8r",
    }
    good_proof = mock_document_state.proofs[0]
    method = {
        "type": "Multikey",
        "publicKeyMultibase": mock_sk.multikey,
    }

    di_jcs_verify(mock_document_state, good_proof, method)

    with pytest.raises(ValueError):
        di_jcs_verify(mock_document_state, bad_proof, method)
