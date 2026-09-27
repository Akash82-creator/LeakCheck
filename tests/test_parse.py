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
    """PSBTv2 stores the spent txid and output index separately, so the
    previous tx can hash correctly while the index points past its outputs."""
    import psbt_edit
    from leakcheck.parse import decode
    maps = psbt_edit.split(decode(_sparrow("p2wpkh_demo_b_psbt_v2")))
    inp = maps[1]
    psbt_edit.drop_field(inp, b"\x01")                 # witness_utxo: keep only the full prev tx
    psbt_edit.set_field(inp, b"\x0f", (7).to_bytes(4, "little"))   # PSBT_IN_OUTPUT_INDEX
    with pytest.raises(LeakCheckError) as e:
        extract(psbt_edit.join(maps))
    assert e.value.code == "utxo_mismatch" and "output 7" in e.value.message


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


@pytest.mark.parametrize("key", [b"\x03", b"\x04"])      # PSBT_OUT_AMOUNT, PSBT_OUT_SCRIPT
def test_output_without_amount_or_script_is_malformed_not_a_crash(key):
    import psbt_edit
    from leakcheck.parse import decode
    maps = psbt_edit.split(decode(_sparrow("p2wpkh_demo_b_psbt_v2")))
    psbt_edit.drop_field(maps[-1], key)                 # last map = last output
    with pytest.raises(LeakCheckError) as e:
        extract(psbt_edit.join(maps))
    assert e.value.code == "malformed"


def test_psbt_edit_roundtrip_is_lossless():
    import psbt_edit
    from leakcheck.parse import decode
    raw = decode(_sparrow("p2wpkh_demo_b_psbt_v2"))
    assert psbt_edit.join(psbt_edit.split(raw)) == raw


@pytest.mark.parametrize("key", [b"\x04", b"\x05"])      # PSBT_GLOBAL_INPUT/OUTPUT_COUNT
def test_psbt_v2_count_bomb_is_rejected_fast(key):
    """embit 0.8.0 would allocate one object per declared input/output first."""
    import time
    import psbt_edit
    from embit import compact
    from leakcheck.parse import decode
    maps = psbt_edit.split(decode(_sparrow("p2wpkh_demo_b_psbt_v2")))
    psbt_edit.set_field(maps[0], key, compact.to_bytes(2 ** 60))
    t = time.monotonic()
    with pytest.raises(LeakCheckError) as e:
        extract(psbt_edit.join(maps))
    assert e.value.code == "malformed" and "Too many" in e.value.message
    assert time.monotonic() - t < 1


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


# ------------------------------------------------ PSBT version rules (BIP174/370)

def _v2_maps():
    import psbt_edit
    from leakcheck.parse import decode
    return psbt_edit.split(decode(_sparrow("p2wpkh_demo_b_psbt_v2")))


def _v0_maps():
    import psbt_edit
    from leakcheck.parse import decode
    return psbt_edit.split(decode(_sparrow("p2wpkh_demo_b")))


def _rejected(maps, words):
    import psbt_edit
    with pytest.raises(LeakCheckError) as e:
        extract(psbt_edit.join(maps))
    assert e.value.code == "malformed" and words in e.value.message, e.value.message


@pytest.mark.parametrize("key,words", [(b"\x02", "TX_VERSION"), (b"\x04", "INPUT_COUNT"),
                                       (b"\x05", "OUTPUT_COUNT")])
def test_v2_required_globals(key, words):
    import psbt_edit
    maps = _v2_maps()
    psbt_edit.drop_field(maps[0], key)
    with pytest.raises(LeakCheckError) as e:
        extract(psbt_edit.join(maps))
    assert e.value.code == "malformed"


def test_v2_tx_version_is_not_silently_defaulted():
    import psbt_edit
    maps = _v2_maps()
    psbt_edit.drop_field(maps[0], b"\x02")
    _rejected(maps, "missing PSBT_GLOBAL_TX_VERSION")


@pytest.mark.parametrize("version", [1, 3, 255])
def test_unknown_psbt_versions_are_rejected(version):
    import psbt_edit
    maps = _v2_maps()
    psbt_edit.set_field(maps[0], b"\xfb", version.to_bytes(4, "little"))
    _rejected(maps, f"Unsupported PSBT version {version}")


def test_v2_fields_without_a_version_are_rejected():
    import psbt_edit
    maps = _v2_maps()
    psbt_edit.drop_field(maps[0], b"\xfb")
    _rejected(maps, "v2-only global fields in a v0 PSBT")


def test_v0_with_v2_only_global_is_rejected():
    import psbt_edit
    maps = _v0_maps()
    psbt_edit.set_field(maps[0], b"\x02", (2).to_bytes(4, "little"))
    _rejected(maps, "v2-only global fields in a v0 PSBT")


def test_v2_fixed_width_fields_must_be_4_bytes():
    import psbt_edit
    maps = _v2_maps()
    psbt_edit.set_field(maps[0], b"\x02", b"\x02\x00")
    _rejected(maps, "must be 4 bytes")


@pytest.mark.parametrize("key", [b"\x0e", b"\x0f"])     # PREVIOUS_TXID, OUTPUT_INDEX
def test_v2_input_required_fields(key):
    import psbt_edit
    maps = _v2_maps()
    psbt_edit.drop_field(maps[1], key)
    with pytest.raises(LeakCheckError) as e:
        extract(psbt_edit.join(maps))
    assert e.value.code in ("malformed", "utxo_mismatch")


@pytest.mark.parametrize("scope", [1, -1])              # an input map, an output map
def test_duplicate_keys_are_rejected(scope):
    import psbt_edit
    maps = _v2_maps()
    maps[scope].append(list(maps[scope][-1]))
    with pytest.raises(LeakCheckError) as e:
        extract(psbt_edit.join(maps))
    assert e.value.code == "malformed"


def test_v2_fallback_locktime_is_optional():
    import psbt_edit
    maps = _v2_maps()
    psbt_edit.drop_field(maps[0], b"\x03")
    assert extract(psbt_edit.join(maps))["locktime"] == 0


@pytest.mark.parametrize("fields,expected", [
    ({b"\x12": 123_456}, 123_456),                      # required height wins over fallback
    ({b"\x11": 600_000_000}, 600_000_000),              # required time
    ({b"\x11": 600_000_000, b"\x12": 123_456}, 123_456),  # both supported: height
])
def test_v2_required_locktime_sets_nlocktime(fields, expected):
    import psbt_edit
    maps = _v2_maps()
    for k, v in fields.items():
        psbt_edit.set_field(maps[1], k, v.to_bytes(4, "little"))
    assert extract(psbt_edit.join(maps))["locktime"] == expected


@pytest.mark.parametrize("drop_script", [True, False])
def test_silent_payments_outputs_are_unsupported_not_misread(drop_script):
    """BIP375: an SP output may have no script yet, and SP change carries no
    BIP32 derivation (it would look like a payment)."""
    import psbt_edit
    maps = _v2_maps()
    out = maps[-1]
    if drop_script:
        psbt_edit.drop_field(out, b"\x04")                 # PSBT_OUT_SCRIPT
    psbt_edit.set_field(out, b"\x09", bytes(66))           # PSBT_OUT_SP_V0_INFO (scan+spend keys)
    with pytest.raises(LeakCheckError) as e:
        extract(psbt_edit.join(maps))
    assert e.value.code == "unsupported" and "Silent Payments" in e.value.message
