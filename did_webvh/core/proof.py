"""Document proof generation and verification."""

from abc import ABC, abstractmethod
from copy import deepcopy
from datetime import datetime
from hashlib import sha256, sha384
from typing import Optional

import aries_askar
import jsoncanon
from multiformats import multibase

from .date_utils import make_timestamp
from .multi_key import MultiKey
from .state import DocumentState

DI_SUPPORTED = [
    {
        "cryptosuite": "eddsa-jcs-2022",
        "algorithm": "ed25519",
        "multicodec_name": "ed25519-pub",
        "hash": sha256,
    },
    {
        "cryptosuite": "ecdsa-jcs-2019",
        "algorithm": "p256",
        "multicodec_name": "p256-pub",
        "hash": sha256,
    },
    {
        "cryptosuite": "ecdsa-jcs-2019",
        "algorithm": "p384",
        "multicodec_name": "p384-pub",
        "hash": sha384,
    },
]


class VerifyingKey(ABC):
    """A public key used for verifying proofs."""

    @property
    @abstractmethod
    def kid(self) -> Optional[str]:
        """Access the key identifier."""

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """Access the key algorithm."""

    @property
    @abstractmethod
    def multicodec_name(self) -> Optional[str]:
        """Access the standard codec identifier as defined by `multicodec`."""

    @property
    @abstractmethod
    def public_key_bytes(self) -> bytes:
        """Access the raw bytes of the public key."""

    @property
    def multikey(self) -> MultiKey:
        """Generate a new `MultiKey` instance from this verifying key."""
        return MultiKey.from_public_key(self.multicodec_name, self.public_key_bytes)


class SigningKey(VerifyingKey):
    """A private keypair used for generating proofs."""

    @abstractmethod
    def sign_message(self, message: bytes) -> bytes:
        """Sign a message with this key, producing a new signature."""


def di_jcs_sign(
    state: DocumentState,
    sk: SigningKey,
    *,
    timestamp: Optional[datetime] = None,
    kid: Optional[str] = None,
) -> dict:
    """Sign a document state with a signing key."""
    return di_jcs_sign_raw(
        state.history_line(),
        sk,
        purpose="authentication",
        timestamp=timestamp,
        kid=kid,
    )


def di_jcs_sign_raw(
    proof_input: dict,
    sk: SigningKey,
    purpose: str,
    *,
    challenge: Optional[str] = None,
    timestamp: Optional[datetime] = None,
    kid: Optional[str] = None,
) -> dict:
    """Sign a dictionary value with a signing key."""
    alg = sk.algorithm
    suite = None
    for opt in DI_SUPPORTED:
        if opt["algorithm"] == alg:
            suite = opt
            break
    if kid is None:
        if not sk.kid:
            raise ValueError("Missing key ID for signing")
        kid = sk.kid
        if not kid.startswith("did:"):
            kid = f"did:key:{kid}#{kid}"
    if not suite:
        raise ValueError(f"Unsupported key algorithm: {alg}")
    options = {
        "type": "DataIntegrityProof",
        "cryptosuite": suite["cryptosuite"],
        "verificationMethod": kid,
        "created": make_timestamp(timestamp)[1],
        "proofPurpose": purpose,
    }
    if challenge:
        options["challenge"] = challenge
    hash_fn = suite["hash"]
    data_hash = hash_fn(di_jcs_canonicalize_input(proof_input)).digest()
    options_hash = hash_fn(jsoncanon.canonicalize(options)).digest()
    sig_input = options_hash + data_hash
    options["proofValue"] = multibase.encode(sk.sign_message(sig_input), "base58btc")
    return options


def di_jcs_verify(state: DocumentState, proof: dict, method: dict):
    """Verify a proof against a document state."""
    return di_jcs_verify_raw(state.history_line(), proof, method)


def di_jcs_verify_raw(proof_input: dict, proof: dict, method: dict):
    """Verify a proof against a dictionary value."""
    if proof.get("type") != "DataIntegrityProof":
        raise ValueError("Unsupported proof type")
    if "proofValue" not in proof or not isinstance(proof["proofValue"], str):
        raise ValueError("Missing or invalid 'proofValue'")
    created = proof.get("created")
    if created:
        make_timestamp(created)  # validate timestamp formatting only

    (codec, key_bytes) = MultiKey(method.get("publicKeyMultibase")).decode()
    suite_name = proof.get("cryptosuite")
    suite = None
    for opt in DI_SUPPORTED:
        if opt["cryptosuite"] == suite_name and opt["multicodec_name"] == codec.name:
            suite = opt
            break
    if not suite:
        raise ValueError(f"Unsupported cryptosuite for proof: {suite_name}/{codec}")
    key = aries_askar.Key.from_public_bytes(suite["algorithm"], key_bytes)
    hash_fn = suite["hash"]
    data_hash = hash_fn(di_jcs_canonicalize_input(proof_input)).digest()
    proof = proof.copy()
    signature = multibase.decode(proof.pop("proofValue"))
    options_hash = hash_fn(jsoncanon.canonicalize(proof)).digest()
    sig_input = options_hash + data_hash
    if not key.verify_signature(sig_input, signature):
        raise ValueError("Invalid signature for proof")


def di_jcs_canonicalize_input(proof_input: dict) -> bytes:
    """Canonicalize a proof input according to JCS."""
    proof_input = deepcopy(proof_input)
    if "proof" in proof_input:
        del proof_input["proof"]
    return jsoncanon.canonicalize(proof_input)
