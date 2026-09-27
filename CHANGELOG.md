# CHANGELOG (spec v4 is frozen; every deviation is logged here with its reason)

## 2026-09-27: fully finalized PSBTs are rejected with an explanation
*(Partly superseded: only finalized PSBTs **without** metadata are rejected; Sparrow keeps
the metadata when finalizing. See "audit against Sparrow 2.2.3's own PSBTs" below.)*

**Reason: test-exposed contradiction in the spec.** §4 said "fully signed PSBTs
accepted", but BIP174 finalizers strip derivation paths, so a finalized PSBT can
never pass precedence step 3. Unsigned and partially signed PSBTs are accepted.
A finalized PSBT with no metadata gets the error `finalized_no_metadata`:
"export it before finalizing."

## 2026-09-27: per-rule change findings are evidence under the verdict
**Reason: spec ambiguity.** §6 gives each change rule a direction (warning or
favorable) *and* a combined verdict. Showing both at top level would count one
leak up to four times. The per-rule findings keep their spec'd kind but carry
`parent="change-verdict"`; only the verdict is top-level. Tests assert both.

## 2026-09-27: change-verdict impact
**Reason: unspecified in §6.** The warning's impact is `high` when the confidence
is `likely`, else `medium`.

## Known consequence of the spec (not a change)
A genuinely changeless payment with no owned outputs is indistinguishable
from a wallet that omits output metadata (§5), so it always shows the degraded
notice and `changeless` stays disabled. `changeless` fires only when an owned
output (e.g. a self-receive) proves that output metadata exists.

## 2026-09-27: E2E fixes (CLI and input formats)
**Reason: bugs found in end-to-end testing.**
- A missing file or directory crashed the CLI with a traceback. It now prints `ERROR (io)` and exits with 2.
- A binary PSBT on stdin was rejected, because stdin was read as text. It's now read as bytes.
- Piping the output into `head` raised BrokenPipeError. That's now handled.
- Hex-text PSBTs and base64 pasted with surrounding quotes are now accepted. This widens what users can paste; it doesn't change the rules.

## 2026-09-27: report layer, local server, docs
**Reason: implementation of §4, §10 and §13 (no rule or wording changes).**
- `report.py` renders one HTML report used by both the web UI and `--html`
  (the Day-5 descope path ships alongside the server, not instead of it).
- The change verdict's card is tagged *Limited*: every change heuristic it
  aggregates has a limited fix (§7). The matching heuristics' own action text
  is shown under Evidence.
- `serve --demo` implements the hosted-demo row of §3.
- Demo PSBTs A/B are synthetic until real Sparrow signet PSBTs replace them.

## 2026-09-27: double-click launchers and `leakcheck open`
**Reason: requested addition beyond spec v4 (makes the private path the easy
path for non-experts, per the Cypherpunk criteria). No rule changes.**
- `leakcheck open` starts the local server and opens the page in the default
  browser once the server is accepting connections. If port 8765 is busy, it
  uses another free port. Still bound to 127.0.0.1 only.
- `LeakCheck-mac.command`, `LeakCheck-windows.bat`, `LeakCheck-linux.sh`:
  double-click launchers. The first run creates `.venv` and installs
  requirements (the only network use); later runs start straight away.
- The package-source URL test now allows exactly one URL: the local page's own
  loopback address, which is needed to open the browser.

## 2026-09-27: audit against Sparrow 2.2.3's own PSBTs
**Reason: correctness and robustness bugs found while testing PSBTs built by
Sparrow's code: by fuzzing them (the output crash and the Taproot memory
exhaustion) and by code review (the UTXO checks). No rule semantics changed.**

Bugs fixed:
- **Unchecked UTXO copy used for values.** When a segwit input carries both
  `non_witness_utxo` and `witness_utxo` (Sparrow always sends both), the
  previous tx was hash-checked but the values were read from `witness_utxo`
  (embit's `utxo` prefers it), which nothing checked. Now the checked
  previous-tx output is used, and a disagreeing `witness_utxo` is rejected
  (`utxo_mismatch`).
- **Crash when the spent output doesn't exist** in the included previous tx
  (`IndexError`). Now `utxo_mismatch`.
- **Crash on an output with no amount or script** (possible in malformed v2
  PSBTs). Now `malformed`. Any other unexpected error while reading fields is
  also reported as `malformed` instead of escaping.
- **Memory exhaustion from a crafted Taproot derivation.** embit 0.8.0 (still
  unfixed upstream) loops over an unchecked leaf-hash count, so ~670 bytes
  could hang the tool and exhaust memory. The count is now checked before embit
  reads the field (subclassed input/output scopes; embit still does all parsing).
- **Server error log could have quoted a PSBT.** Any unexpected error during
  analysis now returns a generic error and logs nothing.
- `small-input` observation said "spent together with 0 other input(s)" when
  every co-spent input was small. Wording only; the rule is unchanged.

Wording changed at the review's request (the spec is otherwise frozen):
- The fingerprint panel is titled "Transaction fingerprint signals" and says it
  is unrelated to the wallet's master key fingerprint. The PSBT version moved
  out of the "visible" table, because it is never broadcast.
- `foreign-input` is described as evidence of another wallet fingerprint (it
  could still be a wallet you control), not as proof of another party or of PayJoin.
- The change-verdict card says it combines the change heuristics and is not
  counted as a separate check (counting itself is unchanged).

Correction to an earlier entry: "BIP174 finalizers strip derivation paths, so
a finalized PSBT can never pass precedence step 3" is **not true for Sparrow**,
which keeps them. Behavior was already right (a finalized PSBT is rejected only
when it has no metadata); the `finalized_no_metadata` message now says "some
wallets remove it" instead of claiming all do.

## 2026-09-27: demo samples now come from Sparrow 2.2.3's code
**Reason: closer to the spec's "Sparrow signet PSBTs" than the synthetic
stand-ins, with the same findings.** `leakcheck/samples/demo_{a,b}.psbt` are
copies of `tests/fixtures/sparrow223_p2wpkh_demo_{a,b}.psbt`, and the golden
snapshots were refreshed. Only transaction data changed (output order, change
amount, nLockTime 200000). `scripts/make_samples.py` was removed: re-running it
would have silently overwritten these samples with synthetic ones. They are
still not GUI exports; see NOTES.md.

## 2026-09-27: final adversarial audit
**Reason: bugs found by an adversarial review of `main`. No rule semantics
changed except one correction to `changeless` (below).**

Bugs fixed:
- **Memory exhaustion from PSBTv2 input/output counts.** embit 0.8.0 (still the
  latest release, and unfixed on its `master`) allocates one object per
  declared `PSBT_GLOBAL_INPUT_COUNT` / `OUTPUT_COUNT` before reading any. A
  count of 2^60 took ~10 s and hit MemoryError under a 1 GB cap; without a cap
  the process would be killed. Counts above 20,000 (more than any standard
  transaction can hold) are now rejected before embit allocates.
- **Request body read fully before the size check.** `/api/analyze` buffered
  the whole body, then compared it with the 1 MB limit. It now refuses an
  oversized `Content-Length` before reading and stops reading at the first
  chunk past the limit. Measured on a live server: a 200 MB streamed upload was
  cut off after ~1.5 MB, and server memory rose ~1.7 MB.
- **`changeless` claimed "there is no change output" when an output of yours
  had a non-standard path.** Such an output is `unknown` and could be change;
  the spec says `unknown` is never guessed. `changeless` is now not applicable
  in that case.
- Launchers: the macOS and Linux wrappers run `scripts/launch.sh` through
  `bash`, so a lost execute bit (some unzip tools) no longer breaks them.

Wording: the favorable change verdict now states its assumption: an output
without your wallet's metadata is treated as a payment.

Tests: two tests that used a fake object or a mocked hash check now use real
PSBTv2 files edited at the key/value level (`tests/psbt_edit.py`). The
no-network test now covers every Sparrow-built fixture and the server path.
