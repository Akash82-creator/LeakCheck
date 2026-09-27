"""Plain data types. No I/O."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

HARDENED = 0x80000000

# (master fingerprint as int, derivation path as a tuple of BIP32 indices)
Derivation = Tuple[int, Tuple[int, ...]]


class LeakCheckError(Exception):
    """The input was rejected. `code` is stable (tests use it); the message
    is written for the user."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class TxIn:
    index: int
    txid: str                 # hex, as stored in the PSBT
    vout: int
    value: int                # sats, taken from UTXO data, never guessed
    spk: str                  # scriptPubKey of the coin being spent (hex)
    script_type: str
    sequence: int
    derivations: List[Derivation] = field(default_factory=list)
    cls: str = "unattributed"  # owned | foreign | unattributed

    @property
    def fingerprints(self) -> set:
        return {fp for fp, _ in self.derivations}


@dataclass
class TxOut:
    index: int
    value: int
    spk: str
    script_type: str
    derivations: List[Derivation] = field(default_factory=list)
    role: str = "external"    # change | self_receive | external | op_return | unknown

    @property
    def fingerprints(self) -> set:
        return {fp for fp, _ in self.derivations}


@dataclass
class NormalizedTx:
    tx_version: int
    locktime: int
    psbt_version: Optional[int]          # None means PSBT v0
    inputs: List[TxIn]
    outputs: List[TxOut]
    wallet_fp: int                       # F
    wallet_fp_source: str                # "inputs" | "internal-chain-output"
    outputs_unverifiable: bool           # degraded mode: no output carries F
    metadata_notes: List[str] = field(default_factory=list)   # ignored metadata

    @property
    def linkable(self) -> List[TxIn]:
        """L = owned + unattributed inputs. Foreign inputs are excluded."""
        return [i for i in self.inputs if i.cls != "foreign"]

    @property
    def foreign_inputs(self) -> List[TxIn]:
        return [i for i in self.inputs if i.cls == "foreign"]

    @property
    def unattributed_inputs(self) -> List[TxIn]:
        return [i for i in self.inputs if i.cls == "unattributed"]

    @property
    def spendable_outputs(self) -> List[TxOut]:
        return [o for o in self.outputs if o.role != "op_return" and o.value > 0]

    @property
    def change_outputs(self) -> List[TxOut]:
        return [o for o in self.outputs if o.role == "change"]


@dataclass
class Finding:
    rule: str
    kind: str                            # warning | favorable | neutral
    observation: str
    inference: str
    action: str
    limits: str
    impact: Optional[str] = None         # high | medium | low
    confidence: Optional[str] = None     # likely | possible
    applicable: bool = True              # False: "not applicable" (Details)
    parent: Optional[str] = None         # set on evidence shown under a verdict

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in (
            "rule", "kind", "impact", "confidence", "observation",
            "inference", "action", "limits", "applicable", "parent")}


@dataclass
class Report:
    findings: List[Finding]
    notices: List[str]                   # always shown at the top
    rule_catalog: List[str]              # every check that could run
    not_checked: List[str]               # spec §9

    def _top(self, kind: str) -> List[Finding]:
        return [f for f in self.findings
                if f.kind == kind and f.applicable and f.parent is None]

    @property
    def warnings(self) -> List[Finding]:
        return self._top("warning")

    @property
    def favorables(self) -> List[Finding]:
        return self._top("favorable")

    @property
    def details(self) -> List[Finding]:
        """Everything that isn't a top-level warning or favorable finding."""
        top = set(map(id, self.warnings + self.favorables))
        return [f for f in self.findings if id(f) not in top]

    def counts(self) -> dict:
        """Honest counts (spec §2). A check counts as applied only if it
        actually ran on this transaction; each catalog rule emits exactly one
        finding, so missing rules can't be silently counted."""
        by_rule = {f.rule: f for f in self.findings if f.rule in self.rule_catalog}
        missing = [r for r in self.rule_catalog if r not in by_rule]
        if missing:
            raise AssertionError(f"rules emitted no finding: {missing}")
        applied = sum(1 for r in self.rule_catalog if by_rule[r].applicable)
        return {"total": len(self.rule_catalog), "applied": applied,
                "not_applicable": len(self.rule_catalog) - applied}

    def by_rule(self, rule: str) -> Optional[Finding]:
        return next((f for f in self.findings if f.rule == rule), None)
