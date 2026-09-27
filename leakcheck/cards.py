"""Action-card text: (rule, kind) -> inference, action, limits (spec §7).

Deterministic, hand-written text. Observations are built in rules.py because
they contain the transaction's actual values. Rules of thumb for editing:
  - never call anything clean, safe or private;
  - never suggest changing an invoice amount;
  - say plainly when a problem can't be fixed in this transaction.
"""

LIMITED = "Limited: "

CARDS = {
    ("common-input-linkage", "warning"): (
        "An observer using the common-input-ownership heuristic concludes these "
        "inputs were controlled together when the transaction was signed.",
        "Before broadcasting, use coin control to pay from a single coin, or "
        "from fewer coins, if one is large enough.",
        "Only this transaction is checked. Coins already linked elsewhere "
        "on-chain stay linked."),
    ("foreign-input", "favorable"): (
        "An observer would link the other party's input(s) to your coins. That "
        "part of the inference is false. Links among your own inputs are "
        "unaffected: see common-input-linkage.",
        "Nothing to change.",
        "This proves nothing about links among your own inputs, or about "
        "anything outside this transaction."),
    ("input-address-reuse", "warning"): (
        "An observer learns this address was funded more than once and links "
        "the coins it received.",
        LIMITED + "the reuse is already on-chain. Don't combine these coins "
        "with others, and use a fresh address for every receive from now on.",
        "Only reuse among this transaction's inputs is visible here. Reuse "
        "across your wallet's history is not checked."),
    ("sender-reuse", "warning"): (
        "An observer can tie this output back to an address you are spending "
        "from, which marks it as coming back to you.",
        "Let your wallet generate a fresh change address and rebuild the "
        "transaction.",
        "Based on exact script matches within this transaction only."),
    ("recipient-reuse", "warning"): (
        "Payments to a reused recipient address are linkable to each other. "
        "This mainly exposes the recipient; it does not by itself reveal your "
        "change.",
        LIMITED + "the recipient chooses their address. You can ask them for "
        "a fresh one.",
        "Based on exact script matches within this transaction only."),
    ("consolidation", "warning"): (
        "An observer concludes all inputs belong to one owner and that the "
        "single output goes back to them. These coins become permanently "
        "linked.",
        "If you don't need to merge these coins now, don't. If you do, do it "
        "knowingly: the link can't be undone after broadcast.",
        "Consolidating can be a reasonable trade-off (e.g. when fees are "
        "low). This tool can't weigh that for you."),
    ("self-transfer", "neutral"): (
        "Every output returns to this wallet, so there is no payment for "
        "change heuristics to contrast against.",
        "Nothing specific to change for the outputs.",
        "Inputs spent together are still linked: see common-input-linkage."),
    ("small-input", "warning"): (
        "An observer links the small coin to your other inputs. Small, "
        "unsolicited coins are sometimes sent specifically to create this "
        "link.",
        "Use coin control to leave the small coin out of this transaction. "
        "Many wallets can freeze a coin so it is never selected automatically.",
        "The tool can't know whether the small coin was unsolicited."),
    ("changeless", "neutral"): (
        "There is no change output, so change-detection heuristics have "
        "nothing to find.",
        "Nothing to change.",
        "This is not a privacy claim. Every other check still applies."),

    # --- change heuristics: per-rule evidence (shown under the verdict) ---
    ("round-payment", "warning"): (
        "Round-amount heuristic: the observer assumes the round output is the "
        "payment and the least round one is change. Here that guess is "
        "CORRECT.",
        LIMITED + "the recipient sets the amount; never alter an invoice. "
        "Options: a coin selection that needs no change output, or PayJoin "
        "(BIP78) if the recipient supports it, which changes the output amounts.",
        "Payments priced in fiat are usually not round in sats and will be "
        "missed. The roundness thresholds are design choices."),
    ("round-payment", "favorable"): (
        "Round-amount heuristic: the observer would pick the least round output "
        "as change. Here that guess is WRONG.",
        "Nothing to change.",
        "The roundness thresholds are design choices."),
    ("script-type-match", "warning"): (
        "Script-type heuristic: the observer assumes change uses the same "
        "address type as the inputs. Here that guess is CORRECT.",
        LIMITED + "the recipient chooses their address type.",
        "P2SH counts as one type; 'unknown' scripts are never used as evidence."),
    ("script-type-match", "favorable"): (
        "Script-type heuristic: the observer would pick the output matching "
        "the inputs' type as change. Here that guess is WRONG.",
        "Nothing to change.",
        "P2SH counts as one type; 'unknown' scripts are never used as evidence."),
    ("optimal-change", "warning"): (
        "Optimal-change heuristic: a sensible wallet adds no unnecessary "
        "inputs, so the one output smaller than every input is presumed "
        "change. Here that guess is CORRECT.",
        LIMITED + "a coin selection with no change output avoids this.",
        "Wallets that deliberately add extra inputs break this heuristic."),
    ("optimal-change", "favorable"): (
        "Optimal-change heuristic: the observer would presume the one output "
        "smaller than every input is change. Here that guess is WRONG.",
        "Nothing to change.",
        "Wallets that deliberately add extra inputs break this heuristic."),

    # --- combined change verdict (top level) ---
    ("change-verdict", "warning"): (
        "An observer weighing these signals independently would identify your "
        "change output, and could follow your remaining funds.",
        "The full fixes before broadcast: a coin selection that needs no "
        "change output, if your coins allow one, or PayJoin (BIP78) if the "
        "recipient supports it.",
        "Each heuristic can be wrong. Confidence reflects how many independent "
        "signals agree; a conflict lowers confidence, never severity."),
    ("change-verdict", "favorable"): (
        "The heuristics implemented here would point an observer at the wrong "
        "output.",
        "Nothing to change.",
        "Heuristics not implemented here might still find your change."),
    ("change-verdict", "neutral"): (
        "None of the implemented change heuristics produced a guess.",
        "Nothing indicated.",
        "Ambiguity under these checks is not proof of privacy."),
}

NEUTRAL_GUESS_ONLY = (
    "This is what an observer would guess. It can't be checked against your "
    "wallet, because no output carries your wallet's metadata.",
    "Nothing can be verified here.",
    "Unverifiable: missing metadata is not evidence either way.")

NO_GUESS = (
    "This heuristic produced no guess for this transaction.",
    "Nothing indicated.",
    "No guess from one heuristic is not proof of privacy.")

NOT_APPLICABLE = (
    "No signal.",
    "Nothing to change.",
    "This check did not apply to this transaction.")

# Spec §9: shown on every report.
NOT_CHECKED = [
    "Address reuse across your wallet's history. A PSBT doesn't contain it, "
    "except reuse among this transaction's own inputs. Often the biggest leak.",
    "Network-level leaks when broadcasting (IP address, node connection).",
    "Timing and amount correlation with other transactions.",
    "Off-chain data (exchange KYC, invoices).",
]

DEGRADED_NOTICE = (
    "No wallet-owned outputs detected. Either this payment has no change, or "
    "your wallet omitted output metadata; LeakCheck can't tell which. Change "
    "checks below show observer guesses only, unverified.")

EMPTY_SUMMARY = ("{applied} of {total} checks applied to this transaction; none "
                 "found a leak; {na} not applicable (see Details). This is not "
                 "proof of privacy.")
