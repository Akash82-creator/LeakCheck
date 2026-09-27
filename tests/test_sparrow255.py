"""PSBTs built by Sparrow 2.5.5's own wallet code (tests/fixtures/sparrow255_*).

Same method and limits as the 2.2.3 set (scripts/sparrow/README.md): Sparrow's
real PSBT code from the signed release, driven headlessly with a made-up coin
history, NOT exported from the GUI. What's new in 2.5.5: PSBTs are v2
internally, and every export menu calls psbt.getForExport(), which converts to
v0 unless Silent Payments are involved. "*_internal_v2" fixtures are the native
v2 before that conversion.

To check a regenerated set:
    LEAKCHECK_SPARROW_FIXTURES=path/to/fixtures python -m pytest tests/test_sparrow255.py
"""

import os
import pathlib

import pytest
from embit.psbt import PSBT

from leakcheck.normalize import normalize
from leakcheck.parse import decode, extract
from leakcheck.report import check, render_fragment

FIXTURES = pathlib.Path(os.environ.get("LEAKCHECK_SPARROW_FIXTURES")
                        or pathlib.Path(__file__).parent / "fixtures")
SPARROW_FP = 0x73C5DA0A


def data(name):
    return (FIXTURES / f"sparrow255_{name}.psbt").read_bytes()


def warns(name):
    report, _ = check(data(name))
    return {f.rule: (f.impact, f.confidence) for f in report.warnings}


ALL = sorted(p.stem[len("sparrow255_"):] for p in FIXTURES.glob("sparrow255_*.psbt"))
EXPORTS = [n for n in ALL if not n.endswith("_internal_v2")]


def test_fixture_set_is_complete():
    assert len(ALL) == 14 and len(EXPORTS) == 12


@pytest.mark.parametrize("name", EXPORTS)
def test_exports_are_psbt_v0(name):
    """What Copy as Base64 / Save PSBT produce in 2.5.5 without Silent Payments."""
    assert PSBT.parse(decode(data(name))).version in (None, 0)


@pytest.mark.parametrize("name", ["p2wpkh_demo_b_internal_v2", "p2tr_two_coins_internal_v2"])
def test_native_v2_parses_and_matches_its_v0_export(name):
    assert PSBT.parse(decode(data(name))).version == 2
    export = name[:-len("_internal_v2")]
    assert warns(name) == warns(export)
    assert normalize(extract(data(name))).locktime == normalize(extract(data(export))).locktime


@pytest.mark.parametrize("name", ALL)
def test_every_psbt_is_owned_and_its_metadata_verifies(name):
    ntx = normalize(extract(data(name)))
    assert ntx.wallet_fp == SPARROW_FP
    assert all(i.cls == "owned" for i in ntx.inputs)
    assert ntx.metadata_notes == []            # every key fits its script


@pytest.mark.parametrize("name", ALL)
def test_global_xpub_is_never_displayed(name):
    psbt = PSBT.parse(decode(data(name)))
    html = render_fragment(*check(data(name)))
    for xpub in psbt.xpubs:
        assert xpub.to_base58() not in html
    assert "tpub" not in html


@pytest.mark.parametrize("name,expected", [
    ("p2wpkh_demo_a", {"common-input-linkage": ("high", "likely"),
                       "small-input": ("medium", "possible"),
                       "change-verdict": ("high", "likely")}),
    ("p2wpkh_demo_b", {"change-verdict": ("high", "likely")}),
    ("p2wpkh_demo_b_file", {"change-verdict": ("high", "likely")}),
    ("p2tr_two_coins", {"common-input-linkage": ("medium", "likely"),
                        "change-verdict": ("high", "likely")}),
    ("p2tr_to_p2tr", {"change-verdict": ("medium", "possible")}),
    ("p2wpkh_trezor_non_witness_utxo", {"change-verdict": ("high", "likely")}),
    ("p2sh_p2wpkh", {"change-verdict": ("high", "likely")}),
    ("p2wpkh_batch", {"change-verdict": ("high", "likely")}),
    ("p2wpkh_signed_only", {"change-verdict": ("high", "likely")}),
    ("p2wpkh_signed_finalized", {"change-verdict": ("high", "likely")}),
])
def test_findings_match_sparrow_223(name, expected):
    assert warns(name) == expected


def test_self_send_to_own_address_is_recognised():
    """The GUI turns a payment to one of the wallet's own addresses into a
    WalletNodePayment, which carries a derivation."""
    report, _ = check(data("p2wpkh_self_send"))
    assert not report.warnings and report.by_rule("self-transfer").applicable


def test_send_max_shows_the_degraded_notice():
    report, _ = check(data("p2wpkh_send_max"))
    assert not report.warnings and report.notices and report.counts()["applied"] == 0
