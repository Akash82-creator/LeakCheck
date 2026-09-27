"""Rule directions, the rounding ladder, batches, and the verdict truth table.
If a test here fails, a rule is pointing the wrong way. Do not 'fix' the test."""

import pytest

from helpers import inp, out, run
from leakcheck.rules import Guess, combine, roundness


# ----------------------------------------------------------- rounding ladder
@pytest.mark.parametrize("v,expected", [
    (99_999, 0), (100_000, 100_000), (1_000_000, 1_000_000), (2_500_000, 100_000),
    (25_000, 1_000), (25_001, 0), (30_000, 10_000), (999, 0), (1_000, 1_000), (0, 0),
])
def test_roundness(v, expected):
    assert roundness(v) == expected


# One input so optimal-change never guesses; all p2wpkh so script-type never
# guesses. Only round-payment speaks in these tests.
def _round_only(pay, change):
    return run([inp(500_000)], [out(pay), out(change, role="change")])


def test_round_payment_reveals_change():
    r = _round_only(100_000, 123_457)
    assert r.by_rule("round-payment").kind == "warning"
    v = r.by_rule("change-verdict")
    assert v.kind == "warning" and v.confidence == "likely"   # strong: payment >= 100k-round


def test_round_change_misleads_observer():
    r = _round_only(123_457, 200_000)
    assert r.by_rule("round-payment").kind == "favorable"
    assert r.by_rule("change-verdict").kind == "favorable"


def test_weak_round_payment_is_possible_not_likely():
    r = _round_only(25_000, 123_457)
    assert r.by_rule("round-payment").kind == "warning"
    assert r.by_rule("change-verdict").confidence == "possible"


@pytest.mark.parametrize("pay,change", [(200_000, 300_000), (123_457, 234_567)])
def test_no_single_least_round_output_means_no_guess(pay, change):
    r = _round_only(pay, change)
    f = r.by_rule("round-payment")
    assert f.kind == "neutral" and f.applicable          # it ran; no guess
    assert r.by_rule("change-verdict").kind == "neutral"


def test_op_return_is_ignored():
    r = run([inp(500_000)], [out(100_000), out(123_457, role="change"),
                             out(0, kind="op_return")])
    assert r.by_rule("round-payment").kind == "warning"


def test_round_batch_three_outputs():
    r = run([inp(1_000_000)], [out(200_000), out(300_000), out(456_789, role="change")])
    assert r.by_rule("round-payment").kind == "warning"
    assert r.by_rule("change-verdict").confidence == "likely"


# --------------------------------------------------------------- script type
def test_matching_change_type_reveals_change():
    r = run([inp(500_000, "p2wpkh")],
            [out(123_457, "p2tr"), out(234_567, "p2wpkh", role="change")])
    assert r.by_rule("script-type-match").kind == "warning"
    assert r.by_rule("change-verdict").confidence == "possible"


def test_matching_payment_type_misleads_observer():
    r = run([inp(500_000, "p2wpkh")],
            [out(123_457, "p2wpkh"), out(234_567, "p2tr", role="change")])
    assert r.by_rule("script-type-match").kind == "favorable"


def test_script_type_batch_three_outputs():
    r = run([inp(900_000, "p2wpkh")],
            [out(123_457, "p2tr"), out(234_567, "p2tr"), out(345_678, "p2wpkh", role="change")])
    assert r.by_rule("script-type-match").kind == "warning"


def test_mixed_input_types_give_no_guess():
    r = run([inp(300_000, "p2wpkh"), inp(300_000, "p2tr")],
            [out(123_457, "p2tr"), out(234_567, "p2wpkh", role="change")])
    assert r.by_rule("script-type-match").kind == "neutral"


# ------------------------------------------------------------ optimal change
def test_output_below_every_input_is_presumed_change():
    r = run([inp(50_000), inp(60_000)], [out(88_123), out(20_877, role="change")])
    assert r.by_rule("optimal-change").kind == "warning"


def test_optimal_change_misled_when_payment_is_smallest():
    r = run([inp(50_000), inp(60_000)], [out(20_877), out(88_123, role="change")])
    assert r.by_rule("optimal-change").kind == "favorable"


# ------------------------------------------------ combined verdict truth table
T, P = 1, 0   # true change is output 1; the payment is output 0


def g(rule, output, strong=False):
    return Guess(rule, output, strong)


@pytest.mark.parametrize("r,s,kind,confidence,conflict", [
    (T, T, "warning", "likely", False),
    (T, None, "warning", "possible", False),
    (None, T, "warning", "possible", False),
    (T, P, "warning", "possible", True),
    (P, T, "warning", "possible", True),
    (P, P, "favorable", None, False),
    (P, None, "favorable", None, False),
    (None, P, "favorable", None, False),
    (None, None, "neutral", None, False),
])
def test_verdict_truth_table(r, s, kind, confidence, conflict):
    v = combine([g("round-payment", r), g("script-type-match", s)], true_change=T)
    assert (v["kind"], v["confidence"], v["conflict"]) == (kind, confidence, conflict)


def test_strong_single_match_is_likely():
    v = combine([g("round-payment", T, strong=True), g("script-type-match", None)], T)
    assert v["confidence"] == "likely"


def test_conflict_caps_confidence_even_when_strong():
    v = combine([g("round-payment", T, strong=True), g("script-type-match", P)], T)
    assert v["kind"] == "warning" and v["confidence"] == "possible"
