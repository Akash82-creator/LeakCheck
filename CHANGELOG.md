# CHANGELOG (spec v4 is frozen; every deviation is logged here with its reason)

## 2026-09-27: fully finalized PSBTs are rejected with an explanation
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
