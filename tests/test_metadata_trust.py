"""Wallet metadata is trusted only as far as it can be checked: a derivation
whose public key doesn't produce the script it is attached to is ignored.
The attacks here are real Sparrow-built PSBTs with tampered metadata."""

import copy
import pathlib

import pytest
from embit import script as escript
from embit.psbt import PSBT

from helpers import F, G, H, chg, inp, out, raw, spk
from leakcheck.model import LeakCheckError
from leakcheck.normalize import normalize
from leakcheck.parse import _key_fits, decode, extract
from leakcheck.report import check

FIX = pathlib.Path(__file__).parent / "fixtures"


def sparrow(name):
    return PSBT.parse(decode((FIX / f"sparrow223_{name}.psbt").read_bytes()))


def roles(psbt):
    return [o.role for o in normalize(extract(psbt.serialize())).outputs]


def test_spoofed_change_on_a_payment_output_is_not_trusted():
    """Your fingerprint and a change path put on someone else's output."""
    p = sparrow("p2wpkh_demo_b")
    ch = next(i for i, o in enumerate(p.outputs) if o.bip32_derivations)
    pay = 1 - ch
    pub, der = next(iter(p.outputs[ch].bip32_derivations.items()))
    p.outputs[pay].bip32_derivations[pub] = der           # same key+path, wrong script
    r = roles(p)
    assert r[pay] == "unknown" and r[ch] == "change"
    report, _ = check(p.serialize())
    assert any("doesn't match its script" in n for n in report.notices)
    assert report.by_rule("change-verdict") is None         # gate refuses to guess
    assert not report.by_rule("round-payment").applicable


def test_spoofed_input_ownership_is_ignored_not_counted_as_foreign():
    p = sparrow("p2wpkh_demo_a")
    other_pub = next(iter(p.inputs[1].bip32_derivations))
    der = next(iter(p.inputs[0].bip32_derivations.values()))
    p.inputs[0].bip32_derivations.clear()
    p.inputs[0].bip32_derivations[other_pub] = der          # a key that isn't this coin's
    ntx = normalize(extract(p.serialize()))
    assert ntx.inputs[0].cls == "unattributed"              # possibly yours, never foreign
    assert ntx.metadata_notes
    report, _ = check(p.serialize())
    assert report.by_rule("common-input-linkage").confidence == "possible"


def test_genuine_sparrow_metadata_all_verifies():
    for f in sorted(FIX.glob("sparrow223_*.psbt")):
        assert normalize(extract(f.read_bytes())).metadata_notes == [], f.name


def test_output_shared_with_another_wallet_stops_as_multisig():
    shared = [chg(3, F), chg(3, G)]
    with pytest.raises(LeakCheckError) as e:
        normalize(raw([inp(500_000)], [out(100_000), out(399_000, "p2wsh", role=shared)]))
    assert e.value.code == "multisig" and "Output 1" in e.value.message


def test_other_wallets_multisig_payment_is_still_just_external():
    theirs = [chg(3, G), chg(3, 0xCCCC0003)]
    ntx = normalize(raw([inp(500_000)], [out(100_000, "p2wsh", role=theirs),
                                         out(399_000, role="change")]))
    assert ntx.outputs[0].role == "external"


# ---------------------------------------------------------------- _key_fits

def _keys():
    from embit.bip32 import HDKey
    root = HDKey.from_seed(bytes(32))
    return root.derive("m/84h/1h/0h/0/0").key, root.derive("m/84h/1h/0h/0/1").key


def test_key_fits_single_key_scripts():
    a, b = _keys()
    for make in (escript.p2pkh, escript.p2wpkh):
        assert _key_fits(make(a).data, a) is True
        assert _key_fits(make(a).data, b) is False
    nested = escript.p2sh(escript.p2wpkh(a)).data
    assert _key_fits(nested, a) is True
    assert _key_fits(nested, b) is None                    # could be another P2SH script
    assert _key_fits(escript.p2tr(a).data, a) is True
    assert _key_fits(escript.p2tr(a).data, b) is False


def test_key_fits_is_unverifiable_where_it_cannot_know():
    a, _ = _keys()
    tr = escript.p2tr(a).data
    assert _key_fits(tr, a, tap_leaves=[b"\x00" * 32]) is None   # script-path key
    assert _key_fits(tr, a, tweaked=True) is None                 # script tree / merkle root
    assert _key_fits(bytes.fromhex(spk("p2wsh")), a) is None


def test_all_input_metadata_failing_says_why():
    p = sparrow("p2wpkh_demo_b")
    other_pub = next(iter(p.outputs[0].bip32_derivations or p.outputs[1].bip32_derivations))
    der = next(iter(p.inputs[0].bip32_derivations.values()))
    p.inputs[0].bip32_derivations.clear()
    p.inputs[0].bip32_derivations[other_pub] = der
    with pytest.raises(LeakCheckError) as e:
        normalize(extract(p.serialize()))
    assert e.value.code == "no_metadata" and "doesn't match their scripts" in e.value.message
