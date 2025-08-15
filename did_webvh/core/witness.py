"""Core witnessing definitions."""

from asyncio import gather, get_running_loop
from dataclasses import dataclass

from .proof import di_jcs_verify, resolve_did_key


@dataclass(frozen=True, slots=True)
class WitnessEntry:
    """A single witness definition."""

    id: str

    @classmethod
    def deserialize(cls, value) -> "WitnessEntry":
        """Deserialize from a dictionary value."""
        if not isinstance(value, dict):
            raise ValueError("Invalid 'witnesses' value, expected dict")
        ident = None
        for k, v in value.items():
            if k == "id":
                ident = v
            else:
                raise ValueError(f"Unexpected key '{k}' in 'witnesses' value")
        if not isinstance(ident, str) or not ident:
            raise ValueError("Expected string for witness identifier")
        return WitnessEntry(ident)


@dataclass(frozen=True, slots=True)
class WitnessRule:
    """Witness configuration rules."""

    threshold: int
    witnesses: tuple[WitnessEntry]

    @classmethod
    # TODO type return None or Witness rule
    def deserialize(cls, value) -> "WitnessRule":
        """Deserialize from a dictionary value."""
        if not isinstance(value, dict):
            raise ValueError("Invalid 'witness' value, expected object")
        if value == {}:
            return None
        threshold = None
        witnesses = None
        for k, v in value.items():
            if k == "threshold":
                threshold = v
            elif k == "witnesses":
                witnesses = v
            else:
                raise ValueError(f"Unexpected key '{k}' in 'witness' value")
        if not isinstance(threshold, int) or threshold < 0:
            raise ValueError(
                "Expected non-negative integer for 'threshold' in 'witness' value"
            )
        if not isinstance(witnesses, list):
            raise ValueError("Expected list for 'witnesses' in 'witness' value")
        witnesses = tuple(WitnessEntry.deserialize(w) for w in witnesses)
        return WitnessRule(threshold, witnesses)


@dataclass
class WitnessChecks:
    """Required witness checks for a document resolution."""

    # a mapping from the rule instance to the earliest versionNumber where it occurs
    rules: dict[WitnessRule, int]
    # a list of all version IDs
    versions: list[str]

    def verify(self, validated: dict, at_version: int | None = None) -> bool:
        """Verify the set of checks against the result of witness proof validation."""
        if not self.versions:
            # must always have at least one version (the genesis)
            return False
        latest_rule = None
        latest_ver = 0
        for rule, ver_num in self.rules.items():
            if at_version is not None and ver_num > at_version:
                continue
            if ver_num > latest_ver:
                latest_rule, latest_ver = rule, ver_num
            total = 0
            for entry in rule.witnesses:
                if entry.id in validated:
                    for check_num, check_ver in validated[entry.id].items():
                        if (
                            check_num >= ver_num
                            and check_num <= len(self.versions)
                            and self.versions[check_num - 1] == check_ver
                        ):
                            total += 1
                            break
            if total < rule.threshold:
                return False
        # latest rule has stricter validation
        if not at_version:
            at_version = len(self.versions)
        if latest_rule and latest_ver >= at_version:
            total = 0
            for entry in latest_rule.witnesses:
                if entry.id in validated:
                    for check_num, check_ver in validated[entry.id].items():
                        if (
                            check_num >= at_version
                            and check_num <= len(self.versions)
                            and self.versions[check_num - 1] == check_ver
                        ):
                            total += 1
                            break
            if total < latest_rule.threshold:
                return False
        return True


async def verify_witness_proofs(proofs: list[dict]) -> tuple[dict, list]:
    """Verify a list of witness proofs.

    Returns: a mapping from `versionId` to a list of `verificationMethod` IDs.
    """
    verified = {}
    errors = []
    tasks = []
    for proof_entry in proofs:
        if not isinstance(proof_entry, dict):
            raise ValueError("Invalid witness proof, expected dict")
        if proof := proof_entry.get("proof"):
            if isinstance(proof, dict):
                proof = [proof]
            if isinstance(proof, list):
                for proof_dict in proof:
                    if isinstance(proof_dict, dict):
                        tasks.append(
                            get_running_loop().run_in_executor(
                                None,
                                _verify_witness_proof,
                                proof_entry,
                                proof_dict,
                                verified,
                                errors,
                            )
                        )
    if tasks:
        await gather(*tasks)
    return (verified, errors)


def _check_version_id(ver_id) -> int:
    if not isinstance(ver_id, str) or not ver_id:
        return 0
    parts = ver_id.split("-", 1)
    if len(parts) < 2:
        return 0
    if not parts[0].isdecimal():
        return 0
    return int(parts[0])


def _verify_witness_proof(container: dict, proof: dict, verified: dict, errors: list):
    method_id = proof.get("verificationMethod")
    try:
        ver_id = container.get("versionId")
        if not (ver_num := _check_version_id(ver_id)):
            raise ValueError("Invalid witness proof, missing or invalid 'versionId'")
        vmethod = resolve_did_key(method_id)
        di_jcs_verify(container, proof, vmethod)
        ident = "did:key:" + vmethod["publicKeyMultibase"]
        if ident not in verified:
            verified[ident] = {}
        verified[ident][ver_num] = ver_id
    except ValueError as err:
        errors.append(err)
