import subprocess
import sys

import pytest

from did_webvh.core.multi_key import MultiKey
from did_webvh.core.proof import di_jcs_verify, resolve_did_key
from did_webvh.core.public_key import PublicKey

MESSAGE = b"did:webvh signature verification test vector"

# (algorithm, multikey, public key, signature), signed with an Askar key
SIGNATURES = (
    (
        "ed25519",
        "z6MktkEGz7PN9Cmycp887FESBHBeGjm7EF5P82Xp6KUQ8L7A",
        "d45c7d8d21623cf77f905c53be3fde5769ebfb3de6d393f7be76e06080698279",
        "d6fb19493b32594ec9da5ddb3ea61ea1d55ca1eeca59158215acee2757048c30"
        "d4ce42442b79b8ec9c0d0b5970064a87498658aafa734e6af436d97611f0e70e",
    ),
    (
        "p256",
        "zDnaeYS6Rt6dRZU5exNz4SgU1yTA6q5cPQquwumJP78gbFEUv",
        "0276e5d8167fbfd6cf44c25fd73ada8cc870ae367c48af8c83b3149deefe473197",
        "2f5edddf5b505e28a4906ab2a7d267e54a085ce12c7997faf6637d1f2cf90baa"
        "94bb0bedf324976837019068ffc471a3d9960981eea99b2833edc8b3b2a991d2",
    ),
    (
        "p384",
        "z82LkpWBujh5Q7VXEKcEDUcSseXqQtH3vnL1gouqr6gXjUYXuv7774qZVDBxH716LFG1ewQ",
        "026c9aa639b4bde570b163f79a41e563410422d5564716e34226088640522856"
        "ce348b15283589df145bea986ff3a70477",
        "6d76547217cf9f1697c7d06897968fbeefbcaff33e892918ffd678ee0a66e845"
        "3a75de02e1b6092d9bc648b9a527a9315b242b65351e09a95b45dfe663d8734a"
        "3e26e8239363cc2ffe952bb1a9c680d3516d46207abacb11677d6001dda2f249",
    ),
)

# Data Integrity proofs over `PROOF_INPUT`, signed with Askar keys
PROOF_INPUT = {"id": "did:example:123", "name": "test document"}
PROOFS = (
    {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": "did:key:z6MkfWBww1Hu23eNC3XpUYiK6rcj62cSuYxDJS73ibLwyXpS"
        "#z6MkfWBww1Hu23eNC3XpUYiK6rcj62cSuYxDJS73ibLwyXpS",
        "created": "2025-01-01T00:00:00Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "z3eDnct3PEcmVfiQVwcRQDpy9UYc8u2fxtREoBVxLK79i2gohFbhnh6VqtqX"
        "Gc3opN4GcrVoG6CJeepDiEAVz8T7P",
    },
    {
        "type": "DataIntegrityProof",
        "cryptosuite": "ecdsa-jcs-2019",
        "verificationMethod": "did:key:zDnaehPY276iTaDSGp5HK48YQvT1TfewnTYjo79QKzqYvmFDQ"
        "#zDnaehPY276iTaDSGp5HK48YQvT1TfewnTYjo79QKzqYvmFDQ",
        "created": "2025-01-01T00:00:00Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "z4jdwkrhhsg4vGTZgtgPcWJygLqeFXGHVndZYPmm8i3oRSoy7sKDvbf1C4k5"
        "HySecYveVGukZMQ5wVtWhLnadvwNu",
    },
    {
        "type": "DataIntegrityProof",
        "cryptosuite": "ecdsa-jcs-2019",
        "verificationMethod": "did:key:z82Lkxj1HbiCQfdC295yHZHKbrRKrUKkqakcnoobPF8C3Xj2"
        "bZTvtjKgYzczNMWMMaZhqDS#z82Lkxj1HbiCQfdC295yHZHKbrRKrUKkqakcnoobPF8C3Xj2bZTvtj"
        "KgYzczNMWMMaZhqDS",
        "created": "2025-01-01T00:00:00Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "z2JHEoQrhCBXoup9hXmpi3kB1xyUD4HoNsejUTRcH3gSALydYvKJDPeJkS5D"
        "kkJiBPM4gvtqC1HnBuU74yYxf6j7vshprcUFBNNTrrm3RWSeWLWaA1yG66bCD1dsuNGY3Fd6X",
    },
)

# Ed25519 edge cases from https://github.com/novifinancial/ed25519-speccheck
# (cases.json): (message, public key, signature, accepted). Only case 3 is
# accepted, which is also the result of the Askar key store for these inputs.
ED25519_EDGE_CASES = (
    (
        "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
        "0000000000000000000000000000000000000000000000000000000000000000",
        False,
    ),
    (
        "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43"
        "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        False,
    ),
    (
        "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"
        "8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
        False,
    ),
    (
        "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f"
        "87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
        True,
    ),
    (
        "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed512"
        "5ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
        False,
    ),
    (
        "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7"
        "e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
        False,
    ),
    (
        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e"
        "547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
        False,
    ),
    (
        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa1942"
        "7e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
        False,
    ),
    (
        "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
        False,
    ),
    (
        "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
        False,
    ),
    (
        "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc"
        "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        False,
    ),
    (
        "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc"
        "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        False,
    ),
)

# Group orders of the supported curves
ECDSA_ORDER = {
    "p256": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    "p384": int(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
        "581a0db248b0a77aecec196accc52973",
        16,
    ),
}


def _is_valid(key: PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        key.verify_signature(message, signature)
    except ValueError:
        return False
    return True


@pytest.mark.parametrize("alg, multikey, public, signature", SIGNATURES)
def test_load_key(alg: str, multikey: str, public: str, signature: str):
    key = PublicKey.from_multikey(multikey)
    assert key.algorithm == alg
    assert key.multicodec_name == f"{alg}-pub"
    assert key.public_key_bytes == bytes.fromhex(public)
    assert key.multikey == multikey
    assert isinstance(key.multikey, MultiKey)
    assert key.kid == multikey
    assert key.get_verification_method() == {
        "type": "Multikey",
        "publicKeyMultibase": multikey,
        "id": multikey,
    }
    key.kid = "did:example:123#key-1"
    assert key.get_verification_method()["id"] == "did:example:123#key-1"

    from_bytes = PublicKey.from_public_bytes(alg, bytes.fromhex(public))
    assert from_bytes.multikey == multikey


@pytest.mark.parametrize("alg, multikey, public, signature", SIGNATURES)
def test_verify_signature(alg: str, multikey: str, public: str, signature: str):
    key = PublicKey.from_multikey(multikey)
    sig = bytes.fromhex(signature)
    assert key.verify_signature(MESSAGE, sig) is None

    assert not _is_valid(key, MESSAGE + b"\0", sig)
    assert not _is_valid(key, MESSAGE, sig[:-1] + bytes([sig[-1] ^ 1]))
    assert not _is_valid(key, MESSAGE, sig[:-1])
    assert not _is_valid(key, MESSAGE, sig + b"\0")
    assert not _is_valid(key, MESSAGE, b"")
    for other_alg, other_multikey, _, _ in SIGNATURES:
        if other_alg != alg:
            assert not _is_valid(PublicKey.from_multikey(other_multikey), MESSAGE, sig)


@pytest.mark.parametrize("alg, multikey, public, signature", SIGNATURES[1:])
def test_verify_ecdsa_signature_values(
    alg: str, multikey: str, public: str, signature: str
):
    key = PublicKey.from_multikey(multikey)
    sig = bytes.fromhex(signature)
    size = len(sig) // 2
    order = ECDSA_ORDER[alg]
    r = int.from_bytes(sig[:size], "big")
    s = int.from_bytes(sig[size:], "big")

    def encode(r: int, s: int) -> bytes:
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")

    assert _is_valid(key, MESSAGE, encode(r, s))
    # both `s` and `n - s` are accepted, as with an Askar key
    assert _is_valid(key, MESSAGE, encode(r, order - s))
    assert not _is_valid(key, MESSAGE, encode(0, s))
    assert not _is_valid(key, MESSAGE, encode(r, 0))
    assert not _is_valid(key, MESSAGE, encode(order, s))
    assert not _is_valid(key, MESSAGE, encode(r, order))


@pytest.mark.parametrize("alg, multikey, public, signature", SIGNATURES[1:])
def test_load_ecdsa_key_encodings(alg: str, multikey: str, public: str, signature: str):
    compressed = bytes.fromhex(public)
    sig = bytes.fromhex(signature)

    # the other point with the same x-coordinate
    flipped = PublicKey(alg, bytes([compressed[0] ^ 1]) + compressed[1:])
    assert flipped.public_key_bytes != compressed
    assert not _is_valid(flipped, MESSAGE, sig)

    for invalid in (
        b"",
        compressed[:-1],
        compressed + b"\0",
        b"\x02" + b"\xff" * (len(compressed) - 1),
    ):
        with pytest.raises(ValueError):
            PublicKey(alg, invalid)


@pytest.mark.parametrize("message, public, signature, accepted", ED25519_EDGE_CASES)
def test_verify_ed25519_edge_cases(
    message: str, public: str, signature: str, accepted: bool
):
    key = PublicKey("ed25519", bytes.fromhex(public))
    assert _is_valid(key, bytes.fromhex(message), bytes.fromhex(signature)) is accepted


def test_load_key_unsupported():
    with pytest.raises(ValueError):
        PublicKey("bls12381g1", b"\0" * 48)
    with pytest.raises(ValueError):
        PublicKey("ed25519", b"\0" * 31)
    with pytest.raises(ValueError):
        PublicKey("ed25519", b"\0" * 33)
    with pytest.raises(ValueError):
        # a secp256k1-pub multikey
        PublicKey.from_multikey("zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")
    with pytest.raises(ValueError):
        PublicKey.from_multikey("not a multikey")


@pytest.mark.parametrize("proof", PROOFS)
def test_verify_proof(proof: dict):
    method = resolve_did_key(proof["verificationMethod"])
    di_jcs_verify(PROOF_INPUT, proof, method)
    di_jcs_verify(
        PROOF_INPUT, proof, PublicKey.from_multikey(method["publicKeyMultibase"])
    )

    with pytest.raises(ValueError):
        di_jcs_verify({**PROOF_INPUT, "name": "other"}, proof, method)
    with pytest.raises(ValueError):
        di_jcs_verify(PROOF_INPUT, {**proof, "created": "2025-01-01T00:00:01Z"}, method)
    for other in PROOFS:
        if other is not proof:
            with pytest.raises(ValueError):
                di_jcs_verify(
                    PROOF_INPUT, proof, resolve_did_key(other["verificationMethod"])
                )


def test_resolve_and_verify_without_askar():
    # A blocked `aries_askar` import stands for an install without the extra.
    script = """
import sys

sys.modules["aries_askar"] = None

import did_webvh.core.proof
import did_webvh.core.resolver
import did_webvh.core.state
import did_webvh.core.witness
import did_webvh.history
import did_webvh.provision
import did_webvh.resolver
import did_webvh.update
import did_webvh.verify

try:
    import did_webvh.askar
except ModuleNotFoundError as err:
    assert "did-webvh[askar]" in str(err), err
else:
    raise AssertionError("did_webvh.askar was imported without aries-askar")
"""
    subprocess.run([sys.executable, "-c", script], check=True)


@pytest.mark.parametrize("alg", ("ed25519", "p256", "p384"))
def test_matches_askar_key(alg: str):
    askar = pytest.importorskip("did_webvh.askar", exc_type=ImportError)

    for _ in range(20):
        sk = askar.AskarSigningKey.generate(alg)
        key = PublicKey.from_multikey(sk.multikey)
        assert key.algorithm == sk.algorithm
        assert key.multicodec_name == sk.multicodec_name
        assert key.public_key_bytes == sk.public_key_bytes
        assert key.multikey == sk.multikey

        sig = sk.sign_message(MESSAGE)
        key.verify_signature(MESSAGE, sig)
        for message, signature in (
            (MESSAGE + b"\0", sig),
            (MESSAGE, sig[:-1] + bytes([sig[-1] ^ 1])),
        ):
            assert not _is_valid(key, message, signature)
            assert not _is_valid(sk, message, signature)
