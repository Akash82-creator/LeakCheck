"""analyze(NormalizedTx) -> Report. Pure: no I/O, no network, no randomness.

Every rule in RULE_CATALOG emits exactly one Finding (applicable or not), so
the "X of Y checks applied" count is always honest.

The core idea (spec §2): each heuristic runs blind, like an observer, and its
guess is compared with the truth from your wallet's metadata.
  guess == truth -> warning   (the observer's inference would succeed)
  guess != truth -> favorable (the observer would be misled)
  no guess       -> neutral
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import List, Optional

from . import cards
from .config import (LINKAGE_HIGH_THRESHOLD, OPTIMAL_CHANGE_ENABLED, ROUND_LADDER,
                     SMALL_UTXO, STRONG_ROUND)
from .model import Finding, NormalizedTx, Report

INPUT_RULES = ["common-input-linkage", "foreign-input", "input-address-reuse",
               "sender-reuse", "recipient-reuse", "consolidation", "self-transfer",
               "small-input", "changeless"]
CHANGE_RULES = ["round-payment", "script-type-match"] + (
    ["optimal-change"] if OPTIMAL_CHANGE_ENABLED else [])
RULE_CATALOG = INPUT_RULES + CHANGE_RULES


def _finding(rule, kind, observation, text=None, **kw) -> Finding:
    inference, action, limits = text or cards.CARDS[(rule, kind)]
    return Finding(rule=rule, kind=kind, observation=observation,
                   inference=inference, action=action, limits=limits, **kw)


def _na(rule, why, **kw) -> Finding:
    return _finding(rule, "neutral", f"Not applicable: {why}.",
                    text=cards.NOT_APPLICABLE, applicable=False, **kw)


def _sats(v: int) -> str:
    return f"{v:,} sats"


def _owned(out, ntx: NormalizedTx) -> bool:
    return ntx.wallet_fp in out.fingerprints


# ---------------------------------------------------------------- input rules

def common_input_linkage(ntx):
    L = ntx.linkable
    scripts = {i.spk for i in L}
    if len(scripts) < 2:
        return _na("common-input-linkage",
                   "fewer than two distinct addresses among your inputs")
    unattributed = [i for i in L if i.cls == "unattributed"]
    obs = f"{len(L)} of your inputs, from {len(scripts)} different addresses, are spent together."
    if unattributed:
        obs += (f" {len(unattributed)} of them carry no wallet metadata: they may "
                "belong to another party, which this tool cannot tell.")
    return _finding("common-input-linkage", "warning", obs,
                    impact="high" if len(scripts) >= LINKAGE_HIGH_THRESHOLD else "medium",
                    confidence="possible" if unattributed else "likely")


def foreign_input(ntx):
    foreign = ntx.foreign_inputs
    if not foreign:
        return _na("foreign-input", "no input belongs to another wallet")
    return _finding("foreign-input", "favorable",
                    f"{len(foreign)} input(s) carry a different wallet (master key) "
                    "fingerprint than yours. In a PayJoin, that would be the receiver's input.")


def input_address_reuse(ntx):
    counts = Counter(i.spk for i in ntx.linkable)
    reused = {spk: n for spk, n in counts.items() if n >= 2}
    if not reused:
        return _na("input-address-reuse", "no address is spent from twice")
    return _finding("input-address-reuse", "warning",
                    f"{sum(reused.values())} inputs spend coins sent to the same "
                    f"address ({len(reused)} address(es) affected).",
                    impact="medium", confidence="likely")


def sender_reuse(ntx):
    input_spks = {i.spk for i in ntx.linkable}
    back = [o.index for o in ntx.outputs
            if o.role != "op_return" and o.spk in input_spks]
    owned_counts = Counter(o.spk for o in ntx.outputs if _owned(o, ntx))
    dup = [spk for spk, n in owned_counts.items() if n >= 2]
    if not back and not dup:
        return _na("sender-reuse", "no output reuses one of your addresses")
    parts = []
    if back:
        parts.append(f"output(s) {back} pay to an address you are spending from")
    if dup:
        parts.append(f"{len(dup)} of your addresses receive more than one output")
    return _finding("sender-reuse", "warning", "; ".join(parts).capitalize() + ".",
                    impact="high", confidence="likely")


def recipient_reuse(ntx):
    ext = [o for o in ntx.spendable_outputs if o.role == "external"]
    dup = [spk for spk, n in Counter(o.spk for o in ext).items() if n >= 2]
    foreign_spks = {i.spk for i in ntx.foreign_inputs}
    back = [o.index for o in ext if o.spk in foreign_spks]
    if not dup and not back:
        return _na("recipient-reuse", "each recipient address appears once")
    parts = []
    if dup:
        parts.append(f"{len(dup)} recipient address(es) receive more than one output")
    if back:
        parts.append(f"output(s) {back} pay to an address the other party is spending from")
    return _finding("recipient-reuse", "warning", "; ".join(parts).capitalize() + ".",
                    impact="medium", confidence="likely")


def consolidation(ntx):
    if ntx.outputs_unverifiable:
        return _na("consolidation", "output ownership can't be verified (degraded mode)")
    L, spend = ntx.linkable, ntx.spendable_outputs
    if len(L) >= 2 and not ntx.foreign_inputs and len(spend) == 1 and _owned(spend[0], ntx):
        return _finding("consolidation", "warning",
                        f"{len(L)} inputs merge into one output of yours "
                        f"({_sats(spend[0].value)}).",
                        impact="high", confidence="likely")
    return _na("consolidation", "not several inputs merging into one output of yours")


def self_transfer(ntx, consolidation_fired):
    if ntx.outputs_unverifiable:
        return _na("self-transfer", "disabled in degraded mode")
    spend = ntx.spendable_outputs
    if spend and all(_owned(o, ntx) for o in spend) and not consolidation_fired:
        return _finding("self-transfer", "neutral",
                        f"All {len(spend)} spendable outputs return to this wallet.")
    return _na("self-transfer", "at least one output leaves this wallet"
               if not consolidation_fired else "covered by consolidation")


def small_input(ntx):
    L = ntx.linkable
    small = [i for i in L if i.value < SMALL_UTXO]
    if not small or len(L) < 2:
        return _na("small-input", f"no input under {SMALL_UTXO:,} sats spent with others")
    desc = ", ".join(f"input {i.index} ({_sats(i.value)})" for i in small)
    return _finding("small-input", "warning",
                    f"{desc} {'is' if len(small) == 1 else 'are'} spent together with "
                    f"your other inputs ({len(L)} in this transaction).",
                    impact="medium", confidence="possible")


def changeless(ntx):
    if ntx.outputs_unverifiable:
        return _na("changeless", "disabled in degraded mode: a changeless payment "
                   "looks the same as missing output metadata")
    if ntx.change_outputs:
        return _na("changeless", "there is a change output")
    if any(o.role == "unknown" for o in ntx.spendable_outputs):
        # 'unknown' is never guessed: it may be change on a non-standard path.
        return _na("changeless", "an output of yours has a non-standard derivation "
                   "path, so whether it is change can't be told")
    if not any(o.role == "external" for o in ntx.spendable_outputs):
        return _na("changeless", "no payment to anyone else")
    return _finding("changeless", "neutral", "No change output; at least one payment.")


# ----------------------------------------------------------- change heuristics

@dataclass
class Guess:
    rule: str
    output: Optional[int]      # guessed change output index, or None
    strong: bool = False       # only round-payment ever sets this
    note: str = ""


def roundness(v: int) -> int:
    """First unit in ROUND_LADDER dividing v, else 0. Higher = rounder."""
    if v <= 0:
        return 0
    return next((u for u in ROUND_LADDER if v % u == 0), 0)


def guess_round_payment(inputs, outputs) -> Guess:
    """Observer rule: the unique LEAST round output is change."""
    r = {o.index: roundness(o.value) for o in outputs}
    lowest = min(r.values())
    tied = [idx for idx, v in r.items() if v == lowest]
    if len(tied) != 1:
        return Guess("round-payment", None, note="no single least-round output")
    g = tied[0]
    strong = all(v >= STRONG_ROUND for idx, v in r.items() if idx != g)
    return Guess("round-payment", g, strong,
                 note="roundness " + ", ".join(f"output {k}: {v:,}" for k, v in r.items()))


def guess_script_type(inputs, outputs) -> Guess:
    """Observer rule: the unique output with the inputs' shared type is change."""
    types = {i.script_type for i in inputs}
    if len(types) != 1 or "unknown" in types:
        return Guess("script-type-match", None, note="inputs don't share one known type")
    t = types.pop()
    same = [o.index for o in outputs if o.script_type == t]
    if len(same) != 1:
        return Guess("script-type-match", None,
                     note=f"{len(same)} outputs have the inputs' type ({t})")
    return Guess("script-type-match", same[0], note=f"only output of type {t}")


def guess_optimal_change(inputs, outputs) -> Guess:
    """Observer rule: the unique output smaller than every input is change."""
    if len(inputs) < 2:
        return Guess("optimal-change", None, note="needs at least two inputs")
    m = min(i.value for i in inputs)
    below = [o.index for o in outputs if o.value < m]
    if len(below) != 1:
        return Guess("optimal-change", None,
                     note=f"{len(below)} outputs are smaller than the smallest input ({_sats(m)})")
    return Guess("optimal-change", below[0], note=f"only output below {_sats(m)}")


GUESSERS = {"round-payment": guess_round_payment,
            "script-type-match": guess_script_type,
            "optimal-change": guess_optimal_change}


def combine(guesses: List[Guess], true_change: int) -> dict:
    """Combined verdict (spec §6). Pure; tested against the truth table."""
    matches = [g for g in guesses if g.output is not None and g.output == true_change]
    conflicts = [g for g in guesses if g.output is not None and g.output != true_change]
    if matches:
        confident = (len(matches) >= 2 or any(g.strong for g in matches)) and not conflicts
        return {"kind": "warning", "confidence": "likely" if confident else "possible",
                "conflict": bool(conflicts), "matches": len(matches)}
    if conflicts:
        return {"kind": "favorable", "confidence": None, "conflict": False, "matches": 0}
    return {"kind": "neutral", "confidence": None, "conflict": False, "matches": 0}


def change_gate(ntx) -> Optional[str]:
    """None if change heuristics apply in normal mode, else the reason."""
    spend = ntx.spendable_outputs
    change = ntx.change_outputs
    if len(change) != 1 or change[0] not in spend:
        return "needs exactly one change output"
    if not any(o.role == "external" for o in spend):
        return "needs at least one payment to someone else"
    other = sorted({o.role for o in spend} - {"change", "external"})
    if other:
        return f"outputs also include: {', '.join(other)}"
    return None


def change_findings(ntx) -> List[Finding]:
    spend = ntx.spendable_outputs
    out: List[Finding] = []

    # Degraded mode: run blind, report guesses only.
    if ntx.outputs_unverifiable:
        if len(spend) < 2:
            return [_na(r, "fewer than two outputs") for r in CHANGE_RULES]
        for r in CHANGE_RULES:
            g = GUESSERS[r](ntx.inputs, spend)
            if g.output is None:
                out.append(_finding(r, "neutral", f"No guess: {g.note}.", text=cards.NO_GUESS))
            else:
                out.append(_finding(r, "neutral",
                                    f"Observer guess: output {g.output} is change ({g.note}).",
                                    text=cards.NEUTRAL_GUESS_ONLY))
        return out

    why = change_gate(ntx)
    if why:
        return [_na(r, why) for r in CHANGE_RULES]

    true_change = ntx.change_outputs[0].index
    guesses = [GUESSERS[r](ntx.inputs, spend) for r in CHANGE_RULES]
    for g in guesses:
        if g.output is None:
            out.append(_finding(g.rule, "neutral", f"No guess: {g.note}.",
                                text=cards.NO_GUESS, parent="change-verdict"))
        else:
            kind = "warning" if g.output == true_change else "favorable"
            out.append(_finding(g.rule, kind,
                                f"Guesses output {g.output} is change ({g.note}); "
                                f"your change is output {true_change}.",
                                parent="change-verdict"))

    v = combine(guesses, true_change)
    if v["kind"] == "warning":
        obs = f"{v['matches']} heuristic(s) point at your real change (output {true_change})."
        if v["conflict"]:
            obs += " Signals conflict: another heuristic points elsewhere."
        out.insert(0, _finding("change-verdict", "warning", obs,
                               impact="high" if v["confidence"] == "likely" else "medium",
                               confidence=v["confidence"]))
    elif v["kind"] == "favorable":
        out.insert(0, _finding("change-verdict", "favorable",
                               f"Heuristics point away from your real change (output {true_change})."))
    else:
        out.insert(0, _finding("change-verdict", "neutral", "No change heuristic made a guess."))
    return out


# --------------------------------------------------------------------- entry

def analyze(ntx: NormalizedTx) -> Report:
    findings = [common_input_linkage(ntx), foreign_input(ntx), input_address_reuse(ntx),
                sender_reuse(ntx), recipient_reuse(ntx)]
    cons = consolidation(ntx)
    findings += [cons, self_transfer(ntx, cons.kind == "warning" and cons.applicable),
                 small_input(ntx), changeless(ntx)]
    findings += change_findings(ntx)

    notices = []
    if ntx.outputs_unverifiable:
        notices.append(cards.DEGRADED_NOTICE)
    if ntx.wallet_fp_source == "internal-chain-output":
        notices.append("Inputs carry more than one wallet (master key) fingerprint; "
                       "yours was identified as the one that receives the change.")
    return Report(findings=findings, notices=notices,
                  rule_catalog=list(RULE_CATALOG), not_checked=list(cards.NOT_CHECKED))
