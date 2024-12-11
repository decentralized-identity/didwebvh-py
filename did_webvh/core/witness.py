"""Core witnessing definitions."""

from dataclasses import dataclass


@dataclass
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


@dataclass
class WitnessRule:
    """Witness configuration rules."""

    threshold: int
    witnesses: list[WitnessEntry]

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
        witnesses = [WitnessEntry.deserialize(w) for w in witnesses]
        return WitnessRule(threshold, witnesses)
