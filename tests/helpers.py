"""Build raw transaction dicts (the parser's output format) by hand, so rule
tests don't depend on PSBT serialization."""

import itertools

from leakcheck.normalize import normalize
from leakcheck.rules import analyze

H = 0x80000000
F = 0xAAAA0001          # our wallet
G = 0xBBBB0002          # another party

_n = itertools.count(1)


def spk(kind="p2wpkh", n=None):
    n = next(_n) if n is None else n
    return {
        "p2wpkh": "0014" + f"{n:040x}",
        "p2tr": "5120" + f"{n:064x}",
        "p2wsh": "0020" + f"{n:064x}",
        "p2pkh": "76a914" + f"{n:040x}" + "88ac",
        "p2sh": "a914" + f"{n:040x}" + "87",
        "op_return": "6a04deadbeef",
    }[kind]


def recv(i=0, fp=F):
    return (fp, (84 + H, 1 + H, 0 + H, 0, i))


def chg(i=0, fp=F):
    return (fp, (84 + H, 1 + H, 0 + H, 1, i))


def inp(value, kind="p2wpkh", der="own", script=None, finalized=False, seq=0xFFFFFFFD):
    """der: 'own' (F), 'none' (no metadata), 'foreign' (G), or a list."""
    if isinstance(der, list):
        derivations = der
    else:
        derivations = {"own": [recv(next(_n))], "none": [], "foreign": [recv(next(_n), G)]}[der]
    return {"txid": f"{next(_n):064x}", "vout": 0, "value": value,
            "spk": script or spk(kind), "sequence": seq,
            "derivations": derivations, "finalized": finalized}


def out(value, kind="p2wpkh", role="pay", script=None):
    """role: 'pay' (someone else), 'change', 'self' (our receive chain), or a
    list of derivations."""
    if isinstance(role, list):
        derivations = role
    else:
        derivations = {"pay": [], "change": [chg(next(_n))], "self": [recv(next(_n))]}[role]
    return {"value": value, "spk": script or spk(kind), "derivations": derivations}


def raw(inputs, outputs, tx_version=2, locktime=0):
    return {"psbt_version": None, "tx_version": tx_version, "locktime": locktime,
            "inputs": inputs, "outputs": outputs}


def run(inputs, outputs):
    return analyze(normalize(raw(inputs, outputs)))
