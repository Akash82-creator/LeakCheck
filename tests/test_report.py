"""Report rendering: counts, fingerprint panel, layout order, golden snapshots.

Golden files are the full report for demo PSBTs A and B. After an intended
change, regenerate with:  UPDATE_GOLDEN=1 python -m pytest tests/test_report.py
"""

import os
import pathlib

import pytest

from helpers import inp, out, run
from leakcheck.fingerprint import panel
from leakcheck.normalize import normalize
from leakcheck.parse import extract
from leakcheck.report import check, render_fragment, summary
from leakcheck.server import sample_bytes

GOLDEN = pathlib.Path(__file__).parent / "golden"


@pytest.mark.parametrize("name", ["a", "b"])
def test_golden_snapshot(name):
    html = render_fragment(*check(sample_bytes(name)))
    path = GOLDEN / f"demo_{name}.html"
    if os.environ.get("UPDATE_GOLDEN"):
        path.write_text(html)
    assert html == path.read_text(), "report changed; review, then UPDATE_GOLDEN=1"


def test_demo_story_linkage_disappears_round_payment_stays():
    a, _ = check(sample_bytes("a"))
    b, _ = check(sample_bytes("b"))
    assert {f.rule for f in a.warnings} == {"common-input-linkage", "small-input", "change-verdict"}
    assert {f.rule for f in b.warnings} == {"change-verdict"}
    assert b.by_rule("round-payment").kind == "warning"
    html = render_fragment(*check(sample_bytes("b")))
    assert "Limited" in html and "Fixable before broadcast" not in html


def test_summary_with_warnings_counts_honestly():
    r, _ = check(sample_bytes("a"))
    assert summary(r) == ("5 of 12 checks applied to this transaction; 3 warnings, "
                          "0 favorable findings; 7 not applicable (see Details).")


def test_summary_without_warnings_never_claims_privacy():
    r = run([inp(500_000)], [out(123_457), out(234_567, role="change")])
    assert not r.warnings
    assert summary(r) == ("3 of 12 checks applied to this transaction; none found a "
                          "leak; 9 not applicable (see Details). This is not proof of privacy.")
    fp = {"tx_version": 2, "locktime": 0, "sequences": [], "psbt_version": 0, "note": ""}
    text = render_fragment(r, fp).lower().replace("not proof of privacy", "")
    for word in ("clean", "safe", "private"):
        assert word not in text


def test_fingerprint_panel_values():
    fp = panel(normalize(extract(sample_bytes("a"))))
    assert fp["tx_version"] == 2 and fp["locktime"] == 0 and fp["psbt_version"] == 0
    assert fp["sequences"] == ["0xfffffffd"] * 3 and fp["signals_rbf"] is True
    html = render_fragment(*check(sample_bytes("a")))
    assert "0xfffffffd (signals RBF)" in html and "nLockTime" in html


def test_layout_order():
    html = render_fragment(*check(sample_bytes("a")))
    order = [html.index(s) for s in ('class="summary"', 'class="warnings"',
                                     'class="fingerprint"', 'class="not-checked"',
                                     'class="details"')]
    assert order == sorted(order)
    assert html.index("Address reuse across your wallet") < html.index("Network-level")


def test_values_are_escaped():
    from leakcheck.model import LeakCheckError
    from leakcheck.report import render_error
    assert "<script>" not in render_error(LeakCheckError("x", "<script>alert(1)</script>"))


def test_panel_separates_transaction_signals_from_wallet_fingerprint():
    html = render_fragment(*check(sample_bytes("a")))
    panel_html = html[html.index('class="fingerprint"'):html.index('class="not-checked"')]
    assert "Transaction fingerprint signals" in panel_html
    assert "Not related to your wallet's master key fingerprint" in panel_html
    table = panel_html[panel_html.index("<table>"):panel_html.index("</table>")]
    assert "PSBT version" not in table                   # never broadcast, so not "visible"
    assert "never broadcast" in panel_html
