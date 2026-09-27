"""Builds real PSBTs with embit for parser tests. Test-only; synthetic keys."""

from embit import script
from embit.bip32 import HDKey
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput

H = 0x80000000
ROOT = HDKey.from_seed(bytes(32))            # "our" wallet
OTHER = HDKey.from_seed(bytes([1]) * 32)     # another party (PayJoin tests)
FP = int.from_bytes(ROOT.my_fingerprint, "big")
OTHER_FP = int.from_bytes(OTHER.my_fingerprint, "big")


def path(purpose, chain, index):
    return [purpose + H, 1 + H, 0 + H, chain, index]


def pub(root, p):
    return root.derive(p).get_public_key()


def spk_for(kind, root, p):
    k = pub(root, p)
    return {"p2wpkh": script.p2wpkh, "p2tr": script.p2tr, "p2pkh": script.p2pkh}[kind](k)


def _add_derivation(scope, kind, root, p):
    k = pub(root, p)
    dp = DerivationPath(root.my_fingerprint, p)
    if kind == "p2tr":
        scope.taproot_bip32_derivations[k] = ([], dp)
    else:
        scope.bip32_derivations[k] = dp


def build(inputs, outputs, non_witness=False):
    """inputs: list of dicts {value, kind, root, path}; outputs: list of dicts
    {value, kind, root(optional), path(optional), spk(optional)}.
    Returns (psbt_object, prev_txs)."""
    prevs, vins = [], []
    for n, i in enumerate(inputs):
        spk = spk_for(i["kind"], i["root"], i["path"])
        prev = Transaction(vin=[TransactionInput(bytes([n + 1]) * 32, 0)],
                           vout=[TransactionOutput(i["value"], spk)])
        prevs.append(prev)
        vins.append(TransactionInput(prev.txid(), 0, sequence=0xFFFFFFFD))
    vouts = []
    for o in outputs:
        spk = o.get("spk") or spk_for(o["kind"], o.get("root", OTHER), o.get("path", path(84, 0, 99)))
        vouts.append(TransactionOutput(o["value"], spk))
    tx = Transaction(version=2, locktime=0, vin=vins, vout=vouts)
    psbt = PSBT(tx)
    for scope, i, prev in zip(psbt.inputs, inputs, prevs):
        if non_witness:
            scope.non_witness_utxo = prev
        else:
            scope.witness_utxo = prev.vout[0]
        if i.get("derive", True):
            _add_derivation(scope, i["kind"], i["root"], i["path"])
    for scope, o in zip(psbt.outputs, outputs):
        if o.get("derive"):
            _add_derivation(scope, o["kind"], o["root"], o["path"])
    return psbt, prevs


def standard_payment(kind="p2wpkh"):
    """2 of our coins pay a round 100,000 sats to someone else; change back to us."""
    psbt, _ = build(
        inputs=[{"value": 80_000, "kind": kind, "root": ROOT, "path": path(84, 0, 0)},
                {"value": 70_000, "kind": kind, "root": ROOT, "path": path(84, 0, 1)}],
        outputs=[{"value": 100_000, "kind": "p2wpkh", "root": OTHER, "path": path(84, 0, 7)},
                 {"value": 49_123, "kind": kind, "root": ROOT, "path": path(84, 1, 0),
                  "derive": True}])
    return psbt
