"""Regenerate the bundled demo PSBTs (leakcheck/samples/).

These are SYNTHETIC signet-style PSBTs built from fixed test seeds, so the
golden snapshots are reproducible. Replace them with real Sparrow signet PSBTs
for the recorded demo (Day 6), then re-run the golden update:
    UPDATE_GOLDEN=1 python -m pytest tests/test_report.py
Usage: python scripts/make_samples.py
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

import psbt_factory as pf  # noqa: E402

R, O, p = pf.ROOT, pf.OTHER, pf.path
PAY = {"value": 100_000, "kind": "p2wpkh", "root": O, "path": p(84, 0, 50)}


def coin(v, i):
    return {"value": v, "kind": "p2wpkh", "root": R, "path": p(84, 0, i)}


def change(v):
    return {"value": v, "kind": "p2wpkh", "root": R, "path": p(84, 1, 0), "derive": True}


# A: three coins, one of them small, paying a round 100,000 sats.
DEMO_A = ([coin(80_000, 0), coin(70_000, 1), coin(600, 2)], [PAY, change(49_900)])
# B: the same payment from one coin, picked with coin control.
DEMO_B = ([coin(200_000, 3)], [PAY, change(99_000)])


def main():
    out = ROOT / "leakcheck" / "samples"
    out.mkdir(exist_ok=True)
    for name, (ins, outs) in {"demo_a": DEMO_A, "demo_b": DEMO_B}.items():
        psbt, _ = pf.build(ins, outs)
        (out / f"{name}.psbt").write_text(psbt.to_string() + "\n")
        print(f"wrote {name}.psbt")


if __name__ == "__main__":
    main()
