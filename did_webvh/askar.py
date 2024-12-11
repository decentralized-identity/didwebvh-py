"""Askar key store support for signing proofs."""

from typing import Optional

from aries_askar import Key, KeyAlg

from .core.proof import SigningKey


class AskarSigningKey(SigningKey):
    """A signing key managed by an Askar store."""

    def __init__(self, key: Key, *, kid: str = None):
        """Initializer."""
        self.key = key
        self._kid = kid or self.multikey

    @classmethod
    def generate(cls, alg: str) -> "AskarSigningKey":
        """Generate a new, random signing key for a given key algorithm."""
        return AskarSigningKey(Key.generate(alg))

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

    def sign_message(self, message: bytes) -> bytes:
        """Sign a message with this key, producing a new signature."""
        return self.key.sign_message(message)

    @classmethod
    def from_jwk(self, jwk: dict | str | bytes) -> "AskarSigningKey":
        """Load a signing key from a JWK."""
        k = Key.from_jwk(jwk)
        return AskarSigningKey(k)
