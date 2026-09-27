"""PSBTs built by Sparrow 2.2.3's own wallet code (tests/fixtures/sparrow223_*).

Provenance and limits: scripts/sparrow/README.md. In short, these come from
Sparrow's real PSBT-construction code in the signed release, driven headlessly
with a made-up coin history; they were NOT exported from the Sparrow GUI.

Sparrow shuffles output order, so every assertion here is about roles and
findings, never output positions. To check a regenerated set:
    LEAKCHECK_SPARROW_FIXTURES=path/to/fixtures python -m pytest tests/test_sparrow.py
"""

import os
import pathlib

import pytest
from embit.psbt import PSBT

from leakcheck.model import LeakCheckError
from leakcheck.normalize import normalize
from leakcheck.parse import decode, extract
from leakcheck.report import check, render_fragment

FIXTURES = pathlib.Path(os.environ.get("LEAKCHECK_SPARROW_FIXTURES")
                        or pathlib.Path(__file__).parent / "fixtures")
SPARROW_FP = 0x73C5DA0A      # master fingerprint of the "abandon ... about" test seed


def data(name):
    return (FIXTURES / f"sparrow223_{name}.psbt").read_bytes()


def run(name):
    return check(data(name))


def warns(report):
    return {f.rule: (f.impact, f.confidence) for f in report.warnings}


ALL = sorted(p.stem[len("sparrow223_"):] for p in FIXTURES.glob("sparrow223_*.psbt"))


def test_fixture_set_is_complete():
    assert len(ALL) == 13


# ------------------------------------------------------ what Sparrow puts in

@pytest.mark.parametrize("name", ALL)
def test_every_sparrow_psbt_is_accepted_and_owned(name):
    ntx = normalize(extract(data(name)))
    assert ntx.wallet_fp == SPARROW_FP and ntx.wallet_fp_source == "inputs"
    assert all(i.cls == "owned" for i in ntx.inputs)
    assert ntx.psbt_version == (2 if name.endswith("psbt_v2") else None)


@pytest.mark.parametrize("name", ALL)
def test_global_xpub_is_present_in_the_psbt_but_never_displayed(name):
    psbt = PSBT.parse(decode(data(name)))
    assert len(psbt.xpubs) == 1                        # Sparrow always includes it
    html = render_fragment(*run(name))
    for xpub in psbt.xpubs:
        assert xpub.to_base58() not in html
    assert "tpub" not in html and "xpub" not in html


@pytest.mark.parametrize("name", ALL)
def test_utxo_fields_sparrow_writes(name):
    psbt = PSBT.parse(decode(data(name)))
    taproot = name.startswith("p2tr")
    for inp in psbt.inputs:
        assert inp.witness_utxo is not None
        # segwit v0: the full previous tx as well (checked against witness_utxo)
        assert (inp.non_witness_utxo is not None) == (not taproot)
        assert bool(inp.taproot_bip32_derivations) == taproot
        assert bool(inp.bip32_derivations) == (not taproot)


@pytest.mark.parametrize("name", [n for n in ALL if n not in ("p2wpkh_send_max",)])
def test_change_output_carries_the_change_chain_derivation(name):
    ntx = normalize(extract(data(name)))
    assert not ntx.outputs_unverifiable
    assert [o.role for o in ntx.outputs].count("change") == 1


def test_taproot_change_is_found_through_taproot_derivations():
    ntx = normalize(extract(data("p2tr_two_coins")))
    change = [o for o in ntx.outputs if o.role == "change"][0]
    assert change.script_type == "p2tr"
    assert all(i.script_type == "p2tr" for i in ntx.inputs)


# ---------------------------------------------------------- full pipeline

def test_demo_a_three_coins_small_coin_round_payment():
    r, _ = run("p2wpkh_demo_a")
    assert warns(r) == {"common-input-linkage": ("high", "likely"),
                        "small-input": ("medium", "possible"),
                        "change-verdict": ("high", "likely")}
    assert r.by_rule("round-payment").kind == "warning"


@pytest.mark.parametrize("name", ["p2wpkh_demo_b", "p2wpkh_demo_b_file",
                                  "p2wpkh_demo_b_psbt_v2", "p2wpkh_trezor_non_witness_utxo",
                                  "p2wpkh_signed_only", "p2wpkh_signed_finalized"])
def test_one_coin_round_payment(name):
    r, _ = run(name)
    assert warns(r) == {"change-verdict": ("high", "likely")}
    assert r.by_rule("round-payment").kind == "warning"
    assert not r.notices


def test_taproot_two_coins_two_heuristics_agree():
    r, _ = run("p2tr_two_coins")
    assert warns(r) == {"common-input-linkage": ("medium", "likely"),
                        "change-verdict": ("high", "likely")}
    assert r.by_rule("script-type-match").kind == "warning"
    assert r.by_rule("optimal-change").kind == "warning"
    assert r.by_rule("round-payment").kind == "neutral"      # both amounts non-round


def test_taproot_weakly_round_payment_is_only_possible():
    r, fp = run("p2tr_to_p2tr")
    assert warns(r) == {"change-verdict": ("medium", "possible")}   # 150,000: not STRONG_ROUND
    assert fp["locktime"] == 0 and fp["signals_rbf"]        # Sparrow's nSequence anti-fee-sniping


def test_nested_segwit_script_type_gives_change_away():
    r, _ = run("p2sh_p2wpkh")
    assert r.by_rule("script-type-match").kind == "warning"
    assert warns(r) == {"change-verdict": ("high", "likely")}


def test_self_send():
    r, _ = run("p2wpkh_self_send")
    assert not r.warnings
    assert r.by_rule("self-transfer").applicable
    assert r.counts() == {"total": 12, "applied": 1, "not_applicable": 11}


def test_send_max_is_indistinguishable_from_missing_output_metadata():
    r, _ = run("p2wpkh_send_max")
    assert not r.warnings and r.notices                   # degraded-mode notice
    assert r.counts()["applied"] == 0


def test_batch_payment():
    r, _ = run("p2wpkh_batch")
    assert warns(r) == {"change-verdict": ("high", "likely")}
    assert len(normalize(extract(data("p2wpkh_batch"))).outputs) == 3


def test_signed_and_finalized_by_sparrow_keeps_its_metadata():
    raw = extract(data("p2wpkh_signed_finalized"))
    assert all(i["finalized"] and i["derivations"] for i in raw["inputs"])


def test_fingerprint_panel_shows_sparrow_anti_fee_sniping_locktime():
    _, fp = run("p2wpkh_demo_b")
    assert fp["tx_version"] == 2 and fp["locktime"] == 200_000
    assert fp["sequences"] == ["0xfffffffd"]


# ------------------------------------------- tampering with a Sparrow PSBT

def test_witness_utxo_disagreeing_with_previous_tx_is_rejected():
    psbt = PSBT.parse(decode(data("p2wpkh_demo_b")))
    psbt.inputs[0].witness_utxo.value += 1
    with pytest.raises(LeakCheckError) as e:
        extract(psbt.serialize())
    assert e.value.code == "utxo_mismatch"
