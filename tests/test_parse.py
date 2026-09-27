import base64
import json

import pytest

import psbt_factory as pf
from leakcheck.model import LeakCheckError
from leakcheck.normalize import normalize
from leakcheck.parse import extract
from leakcheck.rules import analyze


def test_base64_text_and_binary_parse_identically():
    p = pf.standard_payment()
    assert extract(p.to_string()) == extract(p.serialize()) == extract(p.to_string().encode())


def test_taproot_derivations_are_read():
    ntx = normalize(extract(pf.standard_payment("p2tr").serialize()))
    assert ntx.inputs[0].script_type == "p2tr"
    assert [i.cls for i in ntx.inputs] == ["owned", "owned"]
    assert ntx.outputs[1].role == "change"


def test_missing_utxo_is_an_error():
    p = pf.standard_payment()
    p.inputs[0].witness_utxo = None
    with pytest.raises(LeakCheckError) as e:
        extract(p.serialize())
    assert e.value.code == "missing_utxo"


def test_non_witness_utxo_is_verified():
    p, _ = pf.build([{"value": 50_000, "kind": "p2pkh", "root": pf.ROOT, "path": pf.path(44, 0, 0)}],
                    [{"value": 40_000, "kind": "p2wpkh"}], non_witness=True)
    extract(p.serialize())                                   # genuine prev tx: fine
    _, other_prevs = pf.build([{"value": 99_999, "kind": "p2pkh", "root": pf.ROOT,
                                "path": pf.path(44, 0, 5)}], [], non_witness=True)
    p.inputs[0].non_witness_utxo = other_prevs[0]            # wrong prev tx
    with pytest.raises(LeakCheckError) as e:
        extract(p.serialize())
    assert e.value.code == "utxo_mismatch"


def test_finalized_psbt_is_explained():
    p = pf.standard_payment()
    for scope in p.inputs:
        scope.bip32_derivations.clear()
        scope.final_scriptwitness = None
    from embit.script import Witness
    for scope in p.inputs:
        scope.final_scriptwitness = Witness([b"\x01" * 71, b"\x02" * 33])
    with pytest.raises(LeakCheckError) as e:
        normalize(extract(p.serialize()))
    assert e.value.code == "finalized_no_metadata"


@pytest.mark.parametrize("bad", ["hello", base64.b64encode(b"not a psbt at all").decode(),
                                 b"\x00\x01garbage"])
def test_not_a_psbt(bad):
    with pytest.raises(LeakCheckError) as e:
        extract(bad)
    assert e.value.code == "not_psbt"


def test_truncated_psbt_is_malformed():
    data = pf.standard_payment().serialize()[:40]
    with pytest.raises(LeakCheckError) as e:
        extract(data)
    assert e.value.code == "malformed"


def test_global_xpub_never_reaches_the_report():
    from embit.psbt import DerivationPath
    p = pf.standard_payment()
    xpub = pf.ROOT.derive("m/84h/1h/0h").to_public()
    p.xpubs[xpub] = DerivationPath(pf.ROOT.my_fingerprint, [84 + pf.H, 1 + pf.H, 0 + pf.H])
    raw = extract(p.serialize())
    report = analyze(normalize(raw))
    dumped = json.dumps(raw, default=str) + json.dumps([f.as_dict() for f in report.findings])
    assert xpub.to_base58() not in dumped
    assert "xpub" not in raw and "tpub" not in dumped


# ------------------------------------------------ hostile or broken input

def _sparrow(name):
    import pathlib
    return (pathlib.Path(__file__).parent / "fixtures" / f"sparrow223_{name}.psbt").read_bytes()


def test_edited_previous_transaction_is_rejected():
    from embit.psbt import PSBT as EmbitPSBT
    from leakcheck.parse import decode
    psbt = EmbitPSBT.parse(decode(_sparrow("p2wpkh_demo_b")))
    psbt.inputs[0].witness_utxo = None
    prev = psbt.inputs[0].non_witness_utxo
    prev.vout = []                    # no longer hashes to the txid being spent
    with pytest.raises(LeakCheckError) as e:
        extract(psbt.serialize())
    assert e.value.code == "utxo_mismatch"


def test_vout_index_out_of_range_is_a_clean_error():
    from embit.psbt import PSBT as EmbitPSBT
    from leakcheck.parse import _utxo, decode
    psbt = EmbitPSBT.parse(decode(_sparrow("p2wpkh_demo_b")))
    inp = psbt.inputs[0]
    inp.verify = lambda *a, **k: True                   # pretend the hash matched
    inp.vout = len(inp.non_witness_utxo.vout) + 5
    with pytest.raises(LeakCheckError) as e:
        _utxo(0, inp)
    assert e.value.code == "utxo_mismatch"


def test_taproot_leaf_hash_count_bomb_is_rejected_fast():
    """embit 0.8.0 would loop ~2^60 times here and exhaust memory."""
    import time
    from embit.psbt import PSBT as EmbitPSBT
    from leakcheck.parse import decode
    raw = decode(_sparrow("p2tr_to_p2tr"))
    psbt = EmbitPSBT.parse(raw)
    xonly = next(iter(psbt.inputs[0].taproot_bip32_derivations)).xonly()
    key = b"\x21\x16" + xonly                           # PSBT_IN_TAP_BIP32_DERIVATION
    at = raw.index(key) + len(key)
    length, value = raw[at], raw[at + 1:at + 1 + raw[at]]
    assert value[0] == 0                               # zero leaf hashes
    bomb = b"\xff" + (2 ** 60).to_bytes(8, "little") + value[1:]
    bad = raw[:at] + bytes([len(bomb)]) + bomb + raw[at + 1 + length:]
    t = time.monotonic()
    with pytest.raises(LeakCheckError) as e:
        extract(bad)
    assert e.value.code == "malformed" and time.monotonic() - t < 1


def test_output_without_amount_is_malformed_not_a_crash():
    from leakcheck import parse
    p = pf.standard_payment()

    class NoAmount:
        value, script_pubkey = None, None
    fake = type("P", (), {"inputs": [], "outputs": [NoAmount()], "version": 2,
                          "tx_version": 2, "locktime": 0})()
    with pytest.raises(LeakCheckError) as e:
        parse._fields(fake)
    assert e.value.code == "malformed"
    assert extract(p.serialize())                       # a normal PSBT still parses


def test_mutated_psbts_only_ever_raise_leakcheck_errors():
    """A small deterministic fuzz over real Sparrow-built PSBTs. The full run
    (60,000 mutations) is described in NOTES.md; this keeps a fast slice."""
    import random
    from leakcheck.parse import decode
    from leakcheck.report import check, render_fragment
    seeds = [decode(_sparrow(n)) for n in ("p2wpkh_demo_a", "p2tr_two_coins",
                                           "p2wpkh_demo_b_psbt_v2", "p2sh_p2wpkh")]
    rng = random.Random(7)
    for _ in range(1500):
        b = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 4)):
            i = rng.randrange(5, len(b))
            op = rng.random()
            if op < 0.6:
                b[i] = rng.randrange(256)
            elif op < 0.8:
                del b[i:i + rng.randint(1, 8)]
            else:
                b[i:i] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        try:
            render_fragment(*check(bytes(b)))
        except LeakCheckError:
            pass
