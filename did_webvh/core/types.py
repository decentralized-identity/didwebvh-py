"""Abstract data types."""

from abc import ABC, abstractmethod
from typing import Optional

from .multi_key import MultiKey


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

    def get_verification_method(self) -> dict:
        """Generate a standard verification method block for this key."""
        ident = self.kid
        res = {"type": "Multikey", "publicKeyMultibase": str(self.multikey)}
        if ident:
            res["id"] = ident
        return res

    @abstractmethod
    def verify_signature(self, message: bytes, signature: bytes) -> bytes:
        """Verify a signature over `message` against this public key.

        Raises: `ValueError` on verification failure.
        """


class SigningKey(VerifyingKey):
    """A private keypair used for generating proofs."""

    @abstractmethod
    def sign_message(self, message: bytes) -> bytes:
        """Sign a message with this key, producing a new signature."""
