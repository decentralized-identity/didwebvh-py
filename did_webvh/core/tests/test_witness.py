from did_tdw.askar import AskarSigningKey
from did_tdw.core.proof import di_jcs_sign
from did_tdw.core.witness import verify_witness_proofs


def test_witness_filter():
    sk1 = AskarSigningKey.generate("ed25519")
    pk1 = sk1.multikey
    sk1.kid = f"did:key:{pk1}#{pk1}"
    sk2 = AskarSigningKey.generate("ed25519")
    pk2 = sk2.multikey
    sk2.kid = f"did:key:{pk2}#{pk2}"

    data = [
        {"versionId": "1-..."},
        {"versionId": "2-...", "proof": []},
        {"versionId": "3-...", "proof": None},
        {"versionId": "4-..."},
    ]
    data[0]["proof"] = [
        di_jcs_sign(
            data[0],
            sk1,
        )
    ]
    data[3]["proof"] = [
        di_jcs_sign(
            data[3],
            sk1,
        ),
        di_jcs_sign(
            data[3],
            sk2,
        ),
    ]

    filtered = verify_witness_proofs(data)
    assert filtered == {"1-...": {pk1}, "4-...": {pk1, pk2}}
