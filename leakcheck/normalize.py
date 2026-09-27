"""Raw PSBT fields -> NormalizedTx: ownership, input classes, output roles.

Precedence (spec §5), evaluated in order; the first match wins:
  1. missing UTXO data            -> error (raised in parse.py)
  2. malformed tx                 -> error
  3. no input derivation at all   -> error (a finalized PSBT gets its own message)
  4. an input with >1 fingerprint -> stop: multisig unsupported
  5. identify wallet fingerprint F
  6. classify inputs: owned / foreign / unattributed
Missing metadata is never treated as evidence.
"""

from __future__ import annotations

from typing import Optional

from embit.script import Script

from .model import HARDENED, LeakCheckError, NormalizedTx, TxIn, TxOut

_KNOWN_TYPES = ("p2pkh", "p2sh", "p2wpkh", "p2wsh", "p2tr")


def script_type(spk_hex: str) -> str:
    data = bytes.fromhex(spk_hex)
    if data[:1] == b"\x6a":
        return "op_return"
    try:
        t = Script(data).script_type()
    except Exception:
        t = None
    return t if t in _KNOWN_TYPES else "unknown"


def chain_of(path: tuple) -> Optional[int]:
    """0 (receive) or 1 (change) for a standard .../chain/index path, else None.
    Both of the last two levels must be unhardened; a hardened '1h' is not the
    change chain."""
    if len(path) < 2:
        return None
    chain, index = path[-2], path[-1]
    if chain >= HARDENED or index >= HARDENED:
        return None
    return chain if chain in (0, 1) else None


def _is_change_of(out: dict, fp: int) -> bool:
    return any(f == fp and chain_of(p) == 1 for f, p in out["derivations"])


def _drop_bad(items: list, kind: str, notes: list) -> tuple:
    """Remove derivations whose key provably doesn't fit the script (parse.py
    checks this). Returns (items with trusted derivations only, {index: bad fps})."""
    clean, bad_fps = [], {}
    for n, it in enumerate(items):
        bad = set(map(tuple, it.get("bad_derivations", [])))
        if bad:
            bad_fps[n] = {fp for fp, _ in bad}
            notes.append(f"{kind} {n}: wallet metadata that doesn't match its script "
                         "was ignored.")
        clean.append(dict(it, derivations=[d for d in it["derivations"]
                                           if (d[0], tuple(d[1])) not in bad]))
    return clean, bad_fps


def normalize(raw: dict) -> NormalizedTx:
    notes: list = []
    # Metadata is wallet-supplied: keys that provably don't produce the script
    # they are attached to are not trusted (see parse._key_fits).
    ins, _ = _drop_bad(raw["inputs"], "Input", notes)
    outs, out_bad = _drop_bad(raw["outputs"], "Output", notes)

    # 2. malformed transaction
    if not outs:
        raise LeakCheckError("zero_outputs", "Malformed transaction: it has no outputs.")
    outpoints = [(i["txid"], i["vout"]) for i in ins]
    if len(set(outpoints)) != len(outpoints):
        raise LeakCheckError("duplicate_outpoint",
                             "Malformed transaction: the same coin is spent twice.")
    total_in = sum(i["value"] for i in ins)
    total_out = sum(o["value"] for o in outs)
    if total_out > total_in:
        raise LeakCheckError(
            "outputs_exceed_inputs",
            f"Malformed transaction: outputs ({total_out:,} sats) exceed "
            f"inputs ({total_in:,} sats).")

    # 3. wallet metadata must exist somewhere
    if not any(i["derivations"] for i in ins):
        if any(i.get("finalized") for i in ins):
            raise LeakCheckError(
                "finalized_no_metadata",
                "This PSBT is finalized and carries no wallet metadata (some "
                "wallets remove it when finalizing). Export it before signing "
                "or finalizing.")
        if any(i.get("bad_derivations") for i in raw["inputs"]):
            raise LeakCheckError(
                "no_metadata",
                "The inputs' wallet metadata doesn't match their scripts, so none "
                "of it can be trusted and the truth comparison is impossible.")
        raise LeakCheckError(
            "no_metadata",
            "This PSBT contains no wallet metadata (no derivation paths), so "
            "the truth comparison is impossible.")

    # 4. multisig
    for n, i in enumerate(ins):
        if len({fp for fp, _ in i["derivations"]}) > 1:
            raise LeakCheckError(
                "multisig",
                f"Input {n} is multisig. Multisig isn't supported yet: only "
                "ownership detection would change; the rules themselves generalize.")

    # 5. wallet fingerprint F
    input_fps = sorted({fp for i in ins for fp, _ in i["derivations"]})
    if len(input_fps) == 1:
        wallet_fp, source = input_fps[0], "inputs"
    else:
        qualifying = [fp for fp in input_fps if any(_is_change_of(o, fp) for o in outs)]
        if len(qualifying) != 1:
            raise LeakCheckError(
                "unidentified_wallet",
                "Inputs come from several wallets and none (or more than one) "
                "has a change output here, so LeakCheck cannot tell which "
                "wallet built this transaction.")
        wallet_fp, source = qualifying[0], "internal-chain-output"

    # 4b. an output shared between this wallet and another (e.g. multisig)
    for n, o in enumerate(outs):
        fps = {fp for fp, _ in o["derivations"]}
        if wallet_fp in fps and len(fps) > 1:
            raise LeakCheckError(
                "multisig",
                f"Output {n} is shared with another wallet (multisig or similar). "
                "Multisig isn't supported yet: LeakCheck can't tell whether it is "
                "your change.")

    # 6. input classes
    inputs = []
    for n, i in enumerate(ins):
        fps = {fp for fp, _ in i["derivations"]}
        cls = "unattributed" if not fps else ("owned" if wallet_fp in fps else "foreign")
        inputs.append(TxIn(index=n, txid=i["txid"], vout=i["vout"], value=i["value"],
                           spk=i["spk"], script_type=script_type(i["spk"]),
                           sequence=i["sequence"], derivations=list(i["derivations"]),
                           cls=cls))

    # output roles relative to F
    outputs = []
    for n, o in enumerate(outs):
        stype = script_type(o["spk"])
        mine = [p for fp, p in o["derivations"] if fp == wallet_fp]
        if stype == "op_return":
            role = "op_return"
        elif wallet_fp in out_bad.get(n, set()):
            role = "unknown"          # your metadata here didn't fit: never guessed
        elif not mine:
            role = "external"
        else:
            chains = {chain_of(p) for p in mine}
            role = {frozenset({1}): "change", frozenset({0}): "self_receive"}.get(
                frozenset(chains), "unknown")
        outputs.append(TxOut(index=n, value=o["value"], spk=o["spk"], script_type=stype,
                             derivations=list(o["derivations"]), role=role))

    outputs_unverifiable = not any(wallet_fp in o.fingerprints for o in outputs)

    return NormalizedTx(tx_version=raw["tx_version"], locktime=raw["locktime"],
                        psbt_version=raw.get("psbt_version"), inputs=inputs,
                        outputs=outputs, wallet_fp=wallet_fp, wallet_fp_source=source,
                        metadata_notes=notes,
                        outputs_unverifiable=outputs_unverifiable)
