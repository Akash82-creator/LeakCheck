"""Design-choice constants (spec §6). These are decisions, not facts."""

# Rounding ladder in sats. roundness(v) = the FIRST unit in this list that
# divides v, else 0. A higher roundness means a rounder amount.
ROUND_LADDER = [1_000_000, 100_000, 10_000, 1_000]

# A round-payment guess is "strong" when every OTHER spendable output
# (i.e. the presumed payments) has roundness >= this value: very round
# payments next to a non-round output are the clearest version of the signal.
STRONG_ROUND = 100_000

# Inputs below this value (sats) co-spent with other linkable inputs trigger
# small-input. A "small output" warning, not the relay-policy meaning of dust.
SMALL_UTXO = 1_000

# common-input-linkage impact becomes "high" at this many distinct scripts.
LINKAGE_HIGH_THRESHOLD = 3

# Optional rule from spec §6; set False to ship without it.
OPTIMAL_CHANGE_ENABLED = True
