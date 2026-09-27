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
