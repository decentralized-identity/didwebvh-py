"""Askar key store support for signing proofs."""

from typing import Optional

from aries_askar import Key, KeyAlg

from .core.multi_key import MultiKey
from .core.types import SigningKey, VerifyingKey

# Supported multicodec names mapped to key algorithms
ALG_SUPPORTED = {"ed25519-pub": "ed25519", "p256-pub": "p256", "p384-pub": "p384"}


class AskarVerifyingKey(VerifyingKey):
    """A verifying key managed by an Askar store."""

    def __init__(self, key: Key, *, kid: str = None):
        """Initializer."""
        self.key = key
        self._kid = kid or self.multikey

    @property
    def algorithm(self) -> str:
        """Access the algorithm of the signing key."""
        return self.key.algorithm.value

    @property
    def kid(self) -> Optional[str]:
        """Access the key identifier of the signing key."""
        return self._kid

    @kid.setter
    def kid(self, value: str):
        self._kid = value

    @property
    def multicodec_name(self) -> Optional[str]:
        """Access the standard codec identifier as defined by `multicodec`."""
        match self.key.algorithm:
            case KeyAlg.ED25519:
                return "ed25519-pub"
            case KeyAlg.P256:
                return "p256-pub"
            case KeyAlg.P384:
                return "p384-pub"

    @property
    def public_key_bytes(self) -> bytes:
        """Access the raw bytes of the public key."""
        return self.key.get_public_bytes()

    @classmethod
    def from_jwk(cls, jwk: dict | str | bytes) -> "AskarVerifyingKey":
        """Load a verifying key from a JWK."""
        k = Key.from_jwk(jwk)
        return AskarVerifyingKey(k)

    @classmethod
    def from_public_bytes(cls, alg: str, public: bytes) -> "AskarVerifyingKey":
        """Load a verifying key from decoded public key bytes."""
        k = Key.from_public_bytes(alg, public)
        return AskarVerifyingKey(k)

    @classmethod
    def from_multikey(cls, multikey: str) -> "AskarVerifyingKey":
        """Load a verifying key from an encoded MultiKey."""
        (codec, key_bytes) = MultiKey(multikey).decode()
        codec = codec.name
        if codec not in ALG_SUPPORTED:
            raise ValueError(f"Unsupported key type: {codec}")
        return AskarVerifyingKey.from_public_bytes(ALG_SUPPORTED[codec], key_bytes)

    def verify_signature(self, message: bytes, signature: bytes) -> bytes:
        """Verify a signature over `message` against this public key.

        Raises: ValueError on verification failure.
        """
        if not self.key.verify_signature(message, signature):
            raise ValueError("Signature verification error")


class AskarSigningKey(AskarVerifyingKey, SigningKey):
    """A signing key managed by an Askar store."""

    @classmethod
    def generate(cls, alg: str) -> "AskarSigningKey":
        """Generate a new, random signing key for a given key algorithm."""
        return AskarSigningKey(Key.generate(alg))

    def sign_message(self, message: bytes) -> bytes:
        """Sign a message with this key, producing a new signature."""
        return self.key.sign_message(message)

    @classmethod
    def from_jwk(cls, jwk: dict | str | bytes) -> "AskarSigningKey":
        """Load a signing key from a JWK."""
        k = Key.from_jwk(jwk)
        return AskarSigningKey(k)

    @classmethod
    def from_secret_bytes(cls, alg: str, secret: bytes) -> "AskarSigningKey":
        """Load a signing key from decoded secret key bytes."""
        k = Key.from_secret_bytes(alg, secret)
        return AskarSigningKey(k)
