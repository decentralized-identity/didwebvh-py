from did_webvh.askar import AskarSigningKey
from did_webvh.core.proof import di_jcs_sign
from did_webvh.core.witness import (
    WitnessChecks,
    WitnessEntry,
    WitnessRule,
    verify_witness_proofs,
)


async def test_verify_witnesses():
    sk1 = AskarSigningKey.generate("ed25519")
    pk1 = sk1.multikey
    id1 = f"did:key:{pk1}"
    sk1.kid = f"{id1}#{pk1}"
    sk2 = AskarSigningKey.generate("ed25519")
    pk2 = sk2.multikey
    id2 = f"did:key:{pk2}"
    sk2.kid = f"{id2}#{pk2}"

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

    (filtered, errors) = await verify_witness_proofs(data)
    assert filtered == {
        id1: {1: "1-...", 4: "4-..."},
        id2: {4: "4-..."},
    }
    assert errors == []

    checks = WitnessChecks(
        rules={
            WitnessRule(
                threshold=1,
                witnesses=(WitnessEntry(id1, 1),),
            ): 4
        },
        versions=["1-...", "2-...", "3-...", "4-..."],
    )
    assert checks.verify(filtered)

    checks = WitnessChecks(
        rules={
            WitnessRule(
                threshold=2,
                witnesses=(WitnessEntry(id1, 1),),
            ): 4
        },
        versions=["1-...", "2-...", "3-...", "4-..."],
    )
    assert not checks.verify(filtered)
