from copy import deepcopy
from datetime import datetime, timezone
from json import JSONDecodeError

import pytest

from did_webvh.askar import AskarSigningKey
from did_webvh.core.hash_utils import HashInfo
from did_webvh.core.state import DocumentState, verify_state_proofs


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
                "serviceEndpoint": "https://example.com%3A5000/whois.vp",
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


def test_initial_document_state():
    # Valid
    DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:domain.example\n",
        },
    )
    DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document='{"@context": ["https://www.w3.org/ns/did/v1"],"id": "did:webvh:{SCID}:domain.example"}',
    )

    # Invalid json document string
    with pytest.raises(JSONDecodeError):
        DocumentState.initial(
            params={
                "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
                "method": "did:webvh:0.4",
            },
            document='{"@context": ["https://www.w3.org/ns/did/v1"],"id": "did:webvh:{SCID}:domain.example",}',
        )
    # Doc id is not a string
    with pytest.raises(ValueError):
        DocumentState.initial(
            params={
                "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
                "method": "did:webvh:0.4",
            },
            document={
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": 10000,
            },
        )
    # No SCID placeholder
    with pytest.raises(ValueError):
        DocumentState.initial(
            params={
                "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
                "method": "did:webvh:0.4",
            },
            document={
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:{NOTSCID}:domain.example\n",
            },
        )


def test_generate_entry_hash():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:domain.example\n",
        },
    )

    generated_hash = doc_state._generate_entry_hash()
    assert isinstance(generated_hash, str)

    hash_info = HashInfo.from_name("sha2-256")
    generated_hash = doc_state._generate_entry_hash(hash_info=hash_info)
    assert isinstance(generated_hash, str)


def test_check_version_id():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:domain.example\n",
        },
    )
    doc_state.check_version_id()

    # Wrong version id
    doc_state.version_id = "1-QmacBLStXRknM45JGFGUnpcBUibBCvNYJEjyUeZcATVC34"
    with pytest.raises(ValueError):
        doc_state.check_version_id()


def test_generate_next_key_hash():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:domain.example\n",
        },
    )
    doc_state.generate_next_key_hash(
        multikey="z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
    )


def test_check_scid_derivation():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:domain.example\n",
        },
    )
    doc_state._check_scid_derivation()

    # version number equals 1
    doc_state.version_number = 2
    with pytest.raises(ValueError):
        doc_state._check_scid_derivation()
    doc_state.version_number = 1
    doc_state._check_scid_derivation()

    # version id must equal scid
    last_version_id = doc_state.last_version_id
    doc_state.last_version_id = "2-QmUuhGnfMoW8P5JCMWUJi4Ns3WkHsStj2ZEhzpMU7PV8QK"
    with pytest.raises(ValueError):
        doc_state._check_scid_derivation()
    doc_state.last_version_id = last_version_id
    doc_state._check_scid_derivation()

    # Wrong timestamp
    timestamp_raw = doc_state.timestamp_raw
    doc_state.timestamp_raw = "2023-09-10T18:15:05Z"
    with pytest.raises(ValueError):
        doc_state._check_scid_derivation()
    doc_state.timestamp_raw = timestamp_raw
    doc_state._check_scid_derivation()


def test_create_next():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:domain.example\n",
        },
    )
    assert isinstance(doc_state.create_next(), DocumentState)


def test_load_history_line():
    valid_line = {
        "versionId": "1-QmX9fVx3xDJVRY15c2zMvjQN7nKPp4hQsazbbDSGxMwRHG",
        "versionTime": "2024-09-10T18:29:27Z",
        "parameters": {
            "updateKeys": ["z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3"],
            "nextKeyHashes": ["QmTnBEPaARViW8ikCA875H8TR21biFPg9rqijdyZG5tzLw"],
            "method": "did:webvh:0.5",
            "scid": "QmQcJ3rAQSyVCjA2P36RUcwf5bQ4ZAB5m9aieqKwWJb7me",
        },
        "state": {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:QmQcJ3rAQSyVCjA2P36RUcwf5bQ4ZAB5m9aieqKwWJb7me:domain.example",
        },
        "proof": [
            {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:key:z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3#z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3",
                "created": "2024-09-10T18:29:27Z",
                "proofPurpose": "authentication",
                "proofValue": "z4ykWbMWsaLz5QtazW6i6v7ax1T99mvkbMKKf33rPbummsuEnZoDa1puQbTfAiVxe6NdWAyjytyMnmi3gQbJAaCvW",
            }
        ],
    }

    DocumentState.load_history_line(
        valid_line,
        {},
    )

    # Invalid list length - no proof
    line = deepcopy(valid_line)
    del line["proof"]
    with pytest.raises(ValueError):
        DocumentState.load_history_line(
            line,
            {},
        )

    # Invalid - Params isn't a dict
    line = deepcopy(valid_line)
    line["parameters"] = (
        '{"updateKeys": ["z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3"],"nextKeyHashes": ["QmTnBEPaARViW8ikCA875H8TR21biFPg9rqijdyZG5tzLw"],"method": "did:webvh:0.5","scid": "QmXwpXEc44Rw8A7u7okUvsg3HC69JAKV6b3wX4thyV7nYe",}'
    )
    with pytest.raises(ValueError):
        DocumentState.load_history_line(
            line,
            {},
        )


def test_load_history_line_with_prev_state():
    prev_state = DocumentState.load_history_line(
        {
            "versionId": "1-QmX9fVx3xDJVRY15c2zMvjQN7nKPp4hQsazbbDSGxMwRHG",
            "versionTime": "2024-09-10T18:29:27Z",
            "parameters": {
                "updateKeys": ["z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3"],
                "nextKeyHashes": ["QmTnBEPaARViW8ikCA875H8TR21biFPg9rqijdyZG5tzLw"],
                "method": "did:webvh:0.5",
                "scid": "QmQcJ3rAQSyVCjA2P36RUcwf5bQ4ZAB5m9aieqKwWJb7me",
            },
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:QmQcJ3rAQSyVCjA2P36RUcwf5bQ4ZAB5m9aieqKwWJb7me:domain.example",
            },
            "proof": [
                {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "verificationMethod": "did:key:z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3#z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3",
                    "created": "2024-09-10T18:29:27Z",
                    "proofPurpose": "authentication",
                    "proofValue": "z4ykWbMWsaLz5QtazW6i6v7ax1T99mvkbMKKf33rPbummsuEnZoDa1puQbTfAiVxe6NdWAyjytyMnmi3gQbJAaCvW",
                }
            ],
        },
        {},
    )

    DocumentState.load_history_line(
        {
            "versionId": "2-QmVRDqG6kCetD54LEcSomsDm7uCpsHbQkdqk7V5J58aV33",
            "versionTime": "2024-09-10T18:29:28Z",
            "parameters": {
                "updateKeys": ["z6MkoSd9jDGV2hyJCb9GiskBPBTY3o4eNs3K9Vr8tCD5Lpkh"],
                "nextKeyHashes": ["QmdkSM2aqyk5Vfcqz4Bw6AKhp3WoFBSL85ydEqAan8UX8A"],
            },
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:QmNTwtP59iQwTK1JjFi3M4zuKkUQUcDspENXEJmSL8zUR9:domain.example",
            },
            "proof": [
                {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "verificationMethod": "did:key:z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3#z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3",
                    "created": "2024-09-10T18:29:28Z",
                    "proofPurpose": "authentication",
                    "proofValue": "z3vmBNQrQME3R9Y1KgZZbmgpSwT4rwVUBVDwkfmzULADGRxosk2GqvVmGLVRmW8j2SV7zHN1UA97uc2pMM5x7X27N",
                }
            ],
        },
        prev_state=prev_state,
    )


def test_jcs_sign_verify(mock_sk):
    mock_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:{SCID}:domain.example\n",
        },
    )
    method = {
        "type": "Multikey",
        "publicKeyMultibase": mock_sk.multikey,
    }
    proof = mock_state.create_proof(mock_sk)
    mock_state.verify_proof(proof, method)
    proof = mock_state.create_proof(
        sk=mock_sk,
        timestamp=datetime.now(),
    )
    mock_state.verify_proof(proof, method)
    proof = mock_state.create_proof(
        sk=mock_sk,
        timestamp=datetime.now(),
        kid="kid",
    )
    mock_state.verify_proof(proof, method)

    proof["proofPurpose"] = "bad proof"
    with pytest.raises(ValueError):
        mock_state.verify_proof(proof, method)


def test_verify_state_proofs(mock_document_state, mock_next_sk):
    verify_state_proofs(mock_document_state, None)

    pk2 = mock_next_sk.multikey
    prev_state = mock_document_state
    current_state = DocumentState(
        params={
            "updateKeys": [pk2],
            "nextKeyHashes": [],
            "method": "did:webvh:0.5",
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

    verify_state_proofs(state=current_state, prev_state=prev_state)

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
        verify_state_proofs(state=current_state, prev_state=prev_state)
