"""Verifying keys loaded from public key material, with no key store."""

from typing import Optional

from Cryptodome.Hash import SHA256, SHA384
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .multi_key import MultiKey
from .types import VerifyingKey

# Supported multicodec names mapped to key algorithms
ALG_SUPPORTED = {"ed25519-pub": "ed25519", "p256-pub": "p256", "p384-pub": "p384"}

# ECDSA key algorithms mapped to the curve name and the message digest
_ECDSA_PARAMS = {"p256": ("P-256", SHA256), "p384": ("P-384", SHA384)}

_ED25519_KEY_LENGTH = 32


class PublicKey(VerifyingKey):
    """A verifying key for Ed25519, P-256 or P-384 signatures.

    Ed25519 signatures are checked with libsodium (PyNaCl) and ECDSA signatures
    with PyCryptodome, so that the proofs of a DID log can be verified without
    the optional Askar key store.
    """

    def __init__(self, alg: str, public: bytes, *, kid: str = None):
        """Initializer.

        Raises: ValueError if the algorithm is not supported or the public key
        bytes are not a valid key for it.
        """
        if alg == "ed25519":
            if len(public) != _ED25519_KEY_LENGTH:
                raise ValueError("Invalid Ed25519 public key length")
            self._key = VerifyKey(bytes(public))
            self._public = bytes(public)
        elif alg in _ECDSA_PARAMS:
            curve_name, _ = _ECDSA_PARAMS[alg]
            self._key = ECC.import_key(bytes(public), curve_name=curve_name)
            # always report the compressed form of the curve point
            self._public = self._key.export_key(format="SEC1", compress=True)
        else:
            raise ValueError(f"Unsupported key type: {alg}")
        self._alg = alg
        self._kid = kid or self.multikey

    @property
    def algorithm(self) -> str:
        """Access the algorithm of the verifying key."""
        return self._alg

    @property
    def kid(self) -> Optional[str]:
        """Access the key identifier of the verifying key."""
        return self._kid

    @kid.setter
    def kid(self, value: str):
        self._kid = value

    @property
    def multicodec_name(self) -> Optional[str]:
        """Access the standard codec identifier as defined by `multicodec`."""
        return f"{self._alg}-pub"

    @property
    def public_key_bytes(self) -> bytes:
        """Access the raw bytes of the public key."""
        return self._public

    @classmethod
    def from_public_bytes(cls, alg: str, public: bytes) -> "PublicKey":
        """Load a verifying key from decoded public key bytes."""
        return PublicKey(alg, public)

    @classmethod
    def from_multikey(cls, multikey: str) -> "PublicKey":
        """Load a verifying key from an encoded MultiKey."""
        (codec, key_bytes) = MultiKey(multikey).decode()
        codec = codec.name
        if codec not in ALG_SUPPORTED:
            raise ValueError(f"Unsupported key type: {codec}")
        return PublicKey(ALG_SUPPORTED[codec], key_bytes)

    def verify_signature(self, message: bytes, signature: bytes) -> bytes:
        """Verify a signature over `message` against this public key.

        ECDSA signatures are expected as the concatenation of `r` and `s`.

        Raises: ValueError on verification failure.
        """
        try:
            if self._alg == "ed25519":
                self._key.verify(message, signature)
            else:
                _, digest = _ECDSA_PARAMS[self._alg]
                DSS.new(self._key, "fips-186-3").verify(digest.new(message), signature)
        except (BadSignatureError, ValueError, TypeError):
            raise ValueError("Signature verification error") from None
