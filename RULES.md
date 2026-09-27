# LeakCheck rules (spec v4)

A wallet-embeddable description of every check. The reference implementation
is `leakcheck/rules.py` (`analyze()` is pure: no I/O). Constants live in
`leakcheck/config.py` and are design choices, not facts.

| Constant | Value |
|---|---|
| `ROUND_LADDER` | 1,000,000 / 100,000 / 10,000 / 1,000 sats |
| `STRONG_ROUND` | 100,000 sats |
| `SMALL_UTXO` | 1,000 sats |
| `LINKAGE_HIGH_THRESHOLD` | 3 distinct scripts |

## 1. Ownership (evaluated in order; first match wins)

1. An input without UTXO data → **error** (values are never guessed).
2. Malformed tx (no outputs, duplicate outpoint, Σout > Σin) → **error**.
3. No input has a derivation → **error**: no truth to compare against.
4. An input lists more than one fingerprint → **stop**: multisig unsupported.
5. Wallet fingerprint **F**: the single input fingerprint; if there are several,
   the unique one that also appears on an internal-chain (`…/1/i`) output.
   Zero or several qualify → **stop**.
6. Inputs: `owned` (has F), `foreign` (another fingerprint), `unattributed`
   (no derivation: treated as possibly yours).

**Linkable set L** = owned ∪ unattributed inputs.

**Output roles** relative to F: `change` (`…/1/i`), `self_receive` (`…/0/i`),
`external` (no F), `op_return`, `unknown` (F on a non-standard or hardened
path; never guessed). *Spendable* = not OP_RETURN and value > 0.

**Degraded mode:** no output carries F. Input rules stay truth-checked; change
rules report observer guesses only (`neutral`, unverifiable); `changeless`,
`self-transfer` and `consolidation` are disabled.

## 2. Input and reuse rules

| Rule | Fires when | Result |
|---|---|---|
| `common-input-linkage` | L has ≥2 distinct scriptPubKeys | warning; high if ≥3 distinct, else medium; `likely` if L is all owned, `possible` if any input is unattributed |
| `foreign-input` | ≥1 foreign input | favorable: the observer wrongly links the other party's coins to yours. Links among your own inputs remain |
| `input-address-reuse` | ≥2 inputs in L share a scriptPubKey | warning, medium |
| `sender-reuse` | an output reuses an L input's scriptPubKey, or ≥2 owned outputs share one | warning, high |
| `recipient-reuse` | ≥2 external outputs share a scriptPubKey, or one reuses a foreign input's | warning, medium (mainly harms the recipient) |
| `consolidation` | ≥2 inputs in L, no foreign inputs, exactly 1 spendable output, owned | warning, high |
| `self-transfer` | all spendable outputs owned, and not a consolidation | neutral |
| `small-input` | an input in L below `SMALL_UTXO` is co-spent with another input in L | warning, medium, `possible` |
| `changeless` | no change output, ≥1 external output | neutral (not a privacy claim) |

## 3. Change heuristics

**Gate:** exactly one `change` output, ≥1 `external` output, and no other roles
among spendable outputs. Any number of outputs (batches are covered).
Each rule guesses one spendable output as change, or makes no guess.

| Rule | Guess |
|---|---|
| `round-payment` | roundness(v) = first ladder unit dividing v, else 0. The unique output with the strictly lowest roundness. Tie → no guess. **Strong** if every other output has roundness ≥ `STRONG_ROUND` |
| `script-type-match` | all inputs share type T and exactly one output has type T → that output |
| `optimal-change` | ≥2 inputs; exactly one output below the smallest input → that output |

Per rule: guess = true change → `warning`; guess ≠ true change → `favorable`;
no guess → `neutral`. These are shown as evidence under one combined verdict.

### Combined verdict

```
matches   = rules whose guess == true change
conflicts = rules whose guess is another output
if matches:
    warning; confidence = likely if (≥2 matches or any strong match) and no conflicts,
             else possible; caveat "signals conflict" if conflicts
             impact = high if likely, else medium
elif conflicts:
    favorable ("an observer would likely misidentify your change")
else:
    neutral ("ambiguous under these checks")
```

| round-payment | script-type | Verdict |
|---|---|---|
| change (strong) | none | warning, likely |
| change | change | warning, likely |
| change | none | warning, possible |
| change | payment | warning, possible, conflict |
| payment | payment / none | favorable |
| none | none | neutral |

## 4. Always shown

- **Fingerprint panel:** nVersion, nLockTime, per-input nSequence (RBF if
  < 0xfffffffe), PSBT version. Visible, not fixable in this transaction.
- **Not checked:** address reuse across wallet history; network-level leaks;
  timing and amount correlation; off-chain data.
- **Count:** "X of Y checks applied". A check that ran but made no guess counts
  as applied; one whose preconditions failed counts as not applicable.
