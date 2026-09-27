from helpers import inp, out, run, spk
from leakcheck.rules import RULE_CATALOG

CASES = [
    ([inp(500_000)], [out(100_000), out(123_457, role="change")]),
    ([inp(50_000), inp(60_000)], [out(109_000, role="change")]),
    ([inp(80_000), inp(70_000)], [out(100_000), out(49_123)]),              # degraded
    ([inp(200_000)], [out(100_000, role="self"), out(99_000, role="change")]),
    ([inp(500_000)], [out(123_457), out(234_567, role="change")]),           # no guesses
]


def test_every_catalog_rule_emits_exactly_one_finding():
    for ins, outs in CASES:
        r = run(ins, outs)
        rules = [f.rule for f in r.findings if f.rule in RULE_CATALOG]
        assert sorted(rules) == sorted(RULE_CATALOG)


def test_a_rule_that_ran_without_a_guess_counts_as_applied():
    r = run([inp(500_000)], [out(123_457), out(234_567, role="change")])
    assert r.by_rule("round-payment").applicable
    c = r.counts()
    assert c["applied"] + c["not_applicable"] == c["total"] == len(RULE_CATALOG)


def test_rules_whose_gate_fails_count_as_not_applicable():
    r = run([inp(200_000)], [out(100_000, role="self"), out(99_000, role="change")])
    for rule in ("round-payment", "script-type-match", "optimal-change"):
        assert not r.by_rule(rule).applicable


def test_every_finding_has_a_full_card():
    for ins, outs in CASES:
        for f in run(ins, outs).findings:
            assert f.observation and f.inference and f.action and f.limits, f.rule
