from helpers import G, chg, inp, out, recv, run, spk


def test_two_owned_inputs_are_linked():
    f = run([inp(50_000), inp(60_000)], [out(100_000)]).by_rule("common-input-linkage")
    assert (f.kind, f.impact, f.confidence) == ("warning", "medium", "likely")


def test_three_distinct_addresses_is_high_impact():
    f = run([inp(50_000), inp(60_000), inp(70_000)], [out(170_000)]).by_rule("common-input-linkage")
    assert f.impact == "high"


def test_same_address_twice_is_reuse_not_linkage():
    s = spk()
    r = run([inp(50_000, script=s), inp(60_000, script=s)], [out(100_000)])
    assert not r.by_rule("common-input-linkage").applicable
    assert r.by_rule("input-address-reuse").kind == "warning"


def test_A1_missing_metadata_never_lowers_severity():
    r = run([inp(50_000), inp(60_000, der="none")], [out(100_000)])
    f = r.by_rule("common-input-linkage")
    assert f.kind == "warning" and f.confidence == "possible"
    assert not r.by_rule("foreign-input").applicable     # missing != foreign


def test_A2_payjoin_keeps_own_linkage_and_adds_favorable():
    r = run([inp(50_000), inp(60_000), inp(40_000, der="foreign")],
            [out(130_000), out(19_000, role="change")])
    assert r.by_rule("common-input-linkage").kind == "warning"
    assert r.by_rule("foreign-input").kind == "favorable"


def test_sender_reuse_output_back_to_input_address():
    s = spk()
    r = run([inp(200_000, script=s)], [out(100_000), out(99_000, role="change", script=s)])
    assert r.by_rule("sender-reuse").kind == "warning"
    assert r.by_rule("sender-reuse").impact == "high"


def test_sender_reuse_two_owned_outputs_same_address():
    s = spk()
    r = run([inp(300_000)], [out(100_000), out(90_000, role=[chg(5)], script=s),
                             out(90_000, role=[chg(5)], script=s)])
    assert r.by_rule("sender-reuse").kind == "warning"


def test_recipient_reuse_is_not_sender_reuse():
    s = spk()
    r = run([inp(300_000)], [out(100_000, script=s), out(100_000, script=s),
                             out(99_000, role="change")])
    assert r.by_rule("recipient-reuse").kind == "warning"
    assert not r.by_rule("sender-reuse").applicable


def test_recipient_reuse_back_to_foreign_input():
    s = spk()
    r = run([inp(100_000), inp(50_000, der="foreign", script=s)],
            [out(120_000, script=s), out(29_000, role="change")])
    assert r.by_rule("recipient-reuse").kind == "warning"


def test_consolidation_beats_self_transfer():
    r = run([inp(50_000), inp(60_000)], [out(109_000, role="change")])
    assert r.by_rule("consolidation").kind == "warning"
    assert not r.by_rule("self-transfer").applicable


def test_self_transfer():
    r = run([inp(200_000)], [out(100_000, role="self"), out(99_000, role="change")])
    st = r.by_rule("self-transfer")
    assert st.kind == "neutral" and st.applicable
    assert not r.by_rule("round-payment").applicable      # change rules don't apply


def test_small_input_boundary():
    assert run([inp(999), inp(60_000)], [out(50_000)]).by_rule("small-input").kind == "warning"
    assert not run([inp(1_000), inp(60_000)], [out(50_000)]).by_rule("small-input").applicable


def test_small_input_alone_is_not_flagged():
    assert not run([inp(999)], [out(500)]).by_rule("small-input").applicable


def test_true_changeless_payment_looks_degraded():
    # One payment, no output of ours: indistinguishable from a wallet that
    # omitted output metadata (spec §5), so changeless stays disabled.
    r = run([inp(100_000)], [out(99_000)])
    assert not r.by_rule("changeless").applicable
    assert r.notices


def test_changeless_fires_when_an_owned_output_proves_metadata_exists():
    r = run([inp(100_000)], [out(60_000), out(39_000, role="self")])
    f = r.by_rule("changeless")
    assert f.applicable and f.kind == "neutral"
