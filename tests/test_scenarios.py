"""Full pipeline on real PSBTs for the demo story and key journeys."""

import psbt_factory as pf
from leakcheck.normalize import normalize
from leakcheck.parse import extract
from leakcheck.rules import analyze

R, O, p = pf.ROOT, pf.OTHER, pf.path


def I(v, i, kind="p2wpkh", root=R):
    return {"value": v, "kind": kind, "root": root, "path": p(84, 0, i)}


def pay(v, kind="p2wpkh", i=50):
    return {"value": v, "kind": kind, "root": O, "path": p(84, 0, i)}


def chg(v, kind="p2wpkh"):
    return {"value": v, "kind": kind, "root": R, "path": p(84, 1, 0), "derive": True}


def report(inputs, outputs):
    psbt, _ = pf.build(inputs, outputs)
    return analyze(normalize(extract(psbt.to_string())))


def warn_rules(r):
    return sorted(f.rule for f in r.warnings)


def test_demo_A_three_coins_small_coin_round_payment():
    r = report([I(80_000, 0), I(70_000, 1), I(600, 2)], [pay(100_000), chg(49_900)])
    assert warn_rules(r) == ["change-verdict", "common-input-linkage", "small-input"]


def test_demo_B_one_coin_linkage_gone_round_payment_stays():
    r = report([I(200_000, 3)], [pay(100_000), chg(99_000)])
    assert warn_rules(r) == ["change-verdict"]
    assert r.by_rule("round-payment").kind == "warning"


def test_payjoin_journey():
    r = report([I(80_000, 0), I(70_000, 1), I(60_000, 9, root=O)], [pay(160_000), chg(49_000)])
    assert "common-input-linkage" in warn_rules(r)
    assert [f.rule for f in r.favorables] == ["foreign-input"]
    assert r.notices          # "inputs come from more than one wallet"


def test_taproot_conflict_journey():
    r = report([I(80_000, 0, "p2tr"), I(70_000, 1, "p2tr")], [pay(123_457), chg(25_000, "p2tr")])
    v = r.by_rule("change-verdict")
    assert v.kind == "warning" and v.confidence == "possible" and "conflict" in v.observation


def test_changeless_journey_is_honest_not_alarming():
    r = report([I(100_000, 0)], [pay(99_000)])
    assert not r.warnings and r.notices
    assert r.counts()["applied"] == 0
