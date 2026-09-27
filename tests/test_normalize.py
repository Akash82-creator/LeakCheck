import pytest

from helpers import F, G, H, chg, inp, out, raw, recv, run
from leakcheck.model import LeakCheckError
from leakcheck.normalize import normalize


def err(inputs, outputs):
    with pytest.raises(LeakCheckError) as e:
        normalize(raw(inputs, outputs))
    return e.value.code


# ------------------------------------------------------ precedence, in order
def test_zero_outputs():
    assert err([inp(1_000)], []) == "zero_outputs"


def test_duplicate_outpoint():
    a = inp(1_000)
    b = dict(inp(2_000), txid=a["txid"], vout=a["vout"])
    assert err([a, b], [out(500)]) == "duplicate_outpoint"


def test_outputs_exceed_inputs():
    assert err([inp(1_000)], [out(2_000)]) == "outputs_exceed_inputs"


def test_no_metadata_is_an_error_not_a_guess():
    assert err([inp(1_000, der="none")], [out(500)]) == "no_metadata"


def test_finalized_psbt_gets_its_own_message():
    assert err([inp(1_000, der="none", finalized=True)], [out(500)]) == "finalized_no_metadata"


def test_multisig_input_stops():
    assert err([inp(1_000, der=[recv(1, F), recv(1, G)])], [out(500)]) == "multisig"


def test_two_wallets_without_change_cannot_be_identified():
    assert err([inp(1_000), inp(1_000, der="foreign")], [out(1_500)]) == "unidentified_wallet"


def test_two_wallets_both_with_change_cannot_be_identified():
    assert err([inp(10_000), inp(10_000, der="foreign")],
               [out(5_000, role=[chg(1, F)]), out(5_000, role=[chg(2, G)]),
                out(9_000)]) == "unidentified_wallet"


def test_wallet_identified_by_change_output():
    ntx = normalize(raw([inp(10_000), inp(10_000, der="foreign")],
                        [out(12_000), out(7_000, role=[chg(1, F)])]))
    assert ntx.wallet_fp == F and ntx.wallet_fp_source == "internal-chain-output"
    assert [i.cls for i in ntx.inputs] == ["owned", "foreign"]


# ------------------------------------------------------------------- roles
def test_hardened_change_chain_is_unknown_not_change():
    weird = (F, (84 + H, 1 + H, 0 + H, 1 + H, 0))
    ntx = normalize(raw([inp(10_000)], [out(5_000), out(4_000, role=[weird])]))
    assert ntx.outputs[1].role == "unknown"


def test_output_roles():
    ntx = normalize(raw([inp(10_000)], [out(1_000), out(2_000, role="change"),
                                        out(3_000, role="self"), out(0, kind="op_return")]))
    assert [o.role for o in ntx.outputs] == ["external", "change", "self_receive", "op_return"]


# ----------------------------------------------------------- degraded mode
def test_degraded_mode_keeps_input_truth_and_guesses_change():
    r = run([inp(80_000), inp(70_000)], [out(100_000), out(49_123)])
    assert r.notices                                          # it says so
    assert r.by_rule("common-input-linkage").kind == "warning"
    rp = r.by_rule("round-payment")
    assert rp.kind == "neutral" and rp.applicable and "Observer guess" in rp.observation
    assert not r.by_rule("changeless").applicable
    assert not r.by_rule("self-transfer").applicable
    assert r.by_rule("change-verdict") is None                # nothing to verify against


@pytest.mark.parametrize("path", [(84 + H, 1 + H, 0 + H, 1, 5 + H),   # hardened index
                                  (1,),                                # too short
                                  (84 + H, 1 + H, 0 + H, 2, 0)])       # chain 2
def test_non_standard_paths_are_unknown_never_change(path):
    ntx = normalize(raw([inp(10_000)], [out(5_000), out(4_000, role=[(F, path)])]))
    assert ntx.outputs[1].role == "unknown"


def test_non_standard_path_does_not_identify_the_wallet():
    weird = (F, (84 + H, 1 + H, 0 + H, 1, 5 + H))
    assert err([inp(10_000), inp(10_000, der="foreign")],
               [out(12_000), out(7_000, role=[weird])]) == "unidentified_wallet"
