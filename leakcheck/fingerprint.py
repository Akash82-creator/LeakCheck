"""Fingerprint panel (spec §8): visible, but not fixable in this transaction.
Display only; no rule logic."""

from .model import NormalizedTx

NOTE = ("These values narrow down which wallet software built this transaction. "
        "The only fix is a different wallet.")


def panel(ntx: NormalizedTx) -> dict:
    seqs = [i.sequence for i in ntx.inputs]
    return {
        "tx_version": ntx.tx_version,
        "locktime": ntx.locktime,
        "sequences": [f"0x{s:08x}" for s in seqs],
        "signals_rbf": any(s < 0xFFFFFFFE for s in seqs),
        "psbt_version": 0 if ntx.psbt_version is None else ntx.psbt_version,
        "note": NOTE,
    }
