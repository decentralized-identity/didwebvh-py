"""Core witnessing definitions."""

import contextlib
from dataclasses import dataclass

from .proof import di_jcs_verify, resolve_did_key


@dataclass(frozen=True, slots=True)
class WitnessEntry:
    """A single witness definition."""

    id: str
    weight: int

    @classmethod
    def deserialize(cls, value) -> "WitnessEntry":
        """Deserialize from a dictionary value."""
        if not isinstance(value, dict):
            raise ValueError("Invalid 'witnesses' value, expected dict")
        ident = None
        weight = None
        for k, v in value.items():
            if k == "id":
                ident = v
            elif k == "weight":
                weight = v
            else:
                raise ValueError(f"Unexpected key '{k}' in 'witnesses' value")
        if not isinstance(ident, str) or not ident:
            raise ValueError("Expected string for witness identifier")
        if not isinstance(weight, int) or weight <= 0:
            raise ValueError("Expected positive integer for witness weight")
        return WitnessEntry(ident, weight)


@dataclass(frozen=True, slots=True)
class WitnessRule:
    """Witness configuration rules."""

    threshold: int
    witnesses: tuple[WitnessEntry]

    @classmethod
    def deserialize(cls, value) -> "WitnessRule":
        """Deserialize from a dictionary value."""
        if not isinstance(value, dict):
            raise ValueError("Invalid 'witness' value, expected dict")
        threshold = None
        witnesses = None
        for k, v in value.items():
            if k == "threshold":
                threshold = v
            elif k == "witnesses":
                witnesses = v
            else:
                raise ValueError(f"Unexpected key '{k}' in 'witness' value")
        if not isinstance(threshold, int):
            raise ValueError("Expected integer for 'threshold' in 'witness' value")
        if not isinstance(witnesses, list):
            raise ValueError("Expected list for 'witnesses' in 'witness' value")
        witnesses = (WitnessEntry.deserialize(w) for w in witnesses)
        return WitnessRule(threshold, witnesses)

    # def verify(self)


@dataclass(frozen=True, slots=True)
class CheckedWitness:
    """The result of a successful witness verification."""

    witness_id: str
    version_id: str


def verify_witness_proofs(proofs: list[dict]) -> dict[str, set[str]]:
    """Verify a list of witness proofs.

    Returns: a mapping from `versionId` to a list of `verificationMethod` IDs.
    """
    res = {}
    for proof_entry in proofs:
        if not isinstance(proof_entry, dict):
            raise ValueError("Invalid witness proof, expected dict")
        ver_id = proof_entry.get("versionId")
        if not isinstance(ver_id, str) or not ver_id:
            raise ValueError("Invalid witness proof, missing or invalid 'versionId'")
        if proof := proof_entry.get("proof"):
            if isinstance(proof, dict):
                proof = [proof]
            if isinstance(proof, list):
                valid = set()
                for proof_dict in proof:
                    if isinstance(proof_dict, dict):
                        method_id = proof_dict.get("verificationMethod")
                        with contextlib.suppress(ValueError):
                            vmethod = resolve_did_key(method_id)
                            di_jcs_verify(proof_entry, proof_dict, vmethod)
                            valid.add(vmethod["publicKeyMultibase"])
                if valid:
                    if ver_id in res:
                        res[ver_id].update(valid)
                    else:
                        res[ver_id] = valid
    return res
