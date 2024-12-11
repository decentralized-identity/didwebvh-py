from datetime import datetime

import pytest

from did_tdw.askar import AskarSigningKey
from did_tdw.core.proof import (
    di_jcs_sign,
    di_jcs_sign_raw,
    di_jcs_verify,
)
from did_tdw.core.state import DocumentState


@pytest.fixture()
def mock_sk() -> AskarSigningKey:
    return AskarSigningKey.from_jwk(
        '{"crv":"Ed25519","kty":"OKP","x":"iWIGdqmPSeg8Ov89VzUrKuLD7pJ8_askEwJGE1R5Zqk","d":"RJDq2-dY85mW1bbDMcrXPObeL-Ud-b8MrPO-iqxajv0"}'
    )


def test_jcs_sign_verify(mock_sk):
    mock_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:tdw:0.4",
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

    proof["proofPurpose"] = "bad proof"
    with pytest.raises(ValueError):
        di_jcs_verify(mock_state, proof, method)


def test_jcs_sign_raw():
    mock_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:tdw:0.4",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:{SCID}:domain.example\n",
        },
    ).history_line()
    result = di_jcs_sign_raw(
        mock_state,
        sk=AskarSigningKey.generate("ed25519"),
        purpose="authentication",
        challenge="challenge",
    )
    assert isinstance(result, dict)
    di_jcs_sign_raw(
        mock_state,
        sk=AskarSigningKey.generate("p256"),
        purpose="authentication",
        challenge="challenge",
    )
    di_jcs_sign_raw(
        mock_state,
        sk=AskarSigningKey.generate("p384"),
        purpose="authentication",
        challenge="challenge",
    )
    with pytest.raises(TypeError):
        di_jcs_sign_raw(
            mock_state,
            sk=AskarSigningKey.generate("bls12381g1g2"),
            purpose="authentication",
            challenge="challenge",
        )
