# LeakCheck

**A pre-broadcast PSBT privacy check.** Paste or drop your PSBT into a local tool
before you broadcast. It plays a blockchain observer, runs the standard
heuristics that observer would use, and compares the observer's guesses with
what your wallet actually did. It tells you which inferences would be
**correct** (a leak) and what you can still change. Nothing leaves your machine.

LeakCheck never calls a transaction "clean", "safe" or "private". With no warnings it says:
*"X of Y checks applied to this transaction; none found a leak; Z not
applicable (see Details). This is not proof of privacy."*

## Quick start (no terminal)

Install Python 3.11 or newer, download this repository, then double-click:

| System | File |
|---|---|
| macOS | `LeakCheck-mac.command` (first time: right-click → Open, because macOS blocks downloaded scripts) |
| Windows | `LeakCheck-windows.bat` |
| Linux | `LeakCheck-linux.sh` (or run it from a terminal) |

LeakCheck opens in your browser. Close the window that appeared to stop it.
The first launch sets up a private Python environment in `.venv`, which
downloads the dependencies once. After that, LeakCheck makes no network requests.

## Quick start (terminal)

```sh
pip install -r requirements.txt        # Python 3.11+
python -m leakcheck open               # local web UI, opened in your browser
python -m leakcheck serve              # local web UI on 127.0.0.1:8765, no browser
python -m leakcheck tx.psbt            # text report (or pipe base64/hex on stdin)
python -m leakcheck tx.psbt --html report.html   # standalone HTML report
python -m leakcheck tx.psbt --json     # machine-readable findings
python -m pytest                       # full test suite
```

`pip install .` also installs a `leakcheck` command.

CI (`.github/workflows/tests.yml`) runs the full suite on Python 3.11 and 3.12
for every pull request and every push to `main`.

**Accepted input:** unsigned, partially signed, or signed PSBTs (v0 or v2) as a
base64 paste, hex, or a binary/base64 `.psbt` file. A finalized PSBT is accepted
if it still carries wallet metadata (Sparrow keeps it); one whose metadata was
removed is rejected with an explanation.

## Validation status

| What | Status |
|---|---|
| Synthetic fixtures | **Tested** |
| PSBTs built by Sparrow 2.2.3's own code (signed release, run headlessly; [how](scripts/sparrow/README.md)) | **Tested**: P2WPKH, P2SH-P2WPKH, Taproot, PSBT v0/v2, signed and finalized |
| A PSBT exported from the Sparrow GUI from a real signet wallet | **Still pending** |
| Other wallets | **Not tested** |

Details and the steps to close the pending row: [`NOTES.md`](NOTES.md).

## How it works: the simulated observer

Your PSBT carries wallet metadata an observer never sees: BIP32 derivation
paths. From these LeakCheck learns the **truth**: which inputs and outputs are
yours, and which output is change. Each heuristic then runs **blind**, and its
result is compared to the truth:

| Observer's inference | Finding |
|---|---|
| would be correct | `warning`: this leaks |
| would be demonstrably false | `favorable`: the observer is misled |
| no signal / not applicable / unverifiable | `neutral` (under Details) |

Worst-case observer: conflicting signals lower **confidence**, never **severity**.
Missing metadata is never treated as evidence. The full rule set is in
[`RULES.md`](RULES.md).

```
input (file drop | paste | CLI path)
  → parse.py      embit → raw fields
  → normalize.py  ownership + roles → NormalizedTx   (pure, no I/O)
  → rules.py      analyze(NormalizedTx) -> Report     (pure, no I/O)
  → report.py     HTML (local web UI or static file)
```

`analyze()` is a pure function. Together with `RULES.md`, it is meant as a
reference implementation of a check that belongs **inside wallets**, where it
would run by default.

## Threat model: what this tool itself reveals

| Mode | Who learns what |
|---|---|
| Local check (CLI or `serve`) | Nobody. The analysis makes zero network requests; a test blocks all sockets and runs it. |
| Broadcasting afterwards | Your wallet or node connection. Out of scope for LeakCheck. |
| Hosted demo (`serve --demo`) | Refuses user PSBTs; only analyzes the bundled signet samples. |

- The server binds to `127.0.0.1` only and refuses requests for any other host name.
- The page is a single HTML file with its CSS and JS inlined. A
  Content-Security-Policy allows exactly that script and style (by hash) and
  nothing else: no CDN, no remote fonts, no analytics. A test scans the built
  HTML for `http://`, `https://` and `//`.
- The page itself makes no request except to the local server. Your *browser*
  may still make its own background connections (Chromium does, even on a blank
  page); that is outside LeakCheck's control.
- PSBTs are analyzed in memory. They are never written to disk or logged; the
  access log is off. `PSBT_GLOBAL_XPUB` is never read or displayed.
- `--html` writes a report file *you* asked for. It contains amounts from your
  transaction: treat it as private.
- To host the demo behind a reverse proxy, the proxy must forward to
  `127.0.0.1` with `Host: localhost`, and the app must run with `--demo`.

## Report layout

1. Notices (e.g. degraded mode) and the honest check count
2. Warnings, with action cards: *Fixable before broadcast* or *Limited*
3. Favorable findings
4. Transaction fingerprint signals: nVersion, nLockTime, nSequence (visible on-chain, not fixable in this transaction; unrelated to your wallet's master key fingerprint)
5. What is **not** checked (history-wide address reuse, network leaks, timing, off-chain data)
6. Details (collapsed): neutral and not-applicable checks

## Demo

`leakcheck/samples/` holds two signet-style PSBTs (also on the web UI's sample buttons):

- **A:** three coins, one of them small (600 sats), paying a round 100,000 sats →
  linkage, small-input and change warnings.
- **B:** the same payment from one coin via coin control → the linkage findings
  disappear; the round-payment finding stays, with its *Limited* card.

A is more linkable than B **under these checks**. Neither is "clean".

> The bundled samples are synthetic (fixed test seeds, `scripts/make_samples.py`).
> Sparrow-built equivalents with the same findings are in `tests/fixtures/`
> (`sparrow223_p2wpkh_demo_{a,b}.psbt`). For the recording, export A and B from
> the Sparrow GUI, then refresh the golden snapshots:
> `UPDATE_GOLDEN=1 python -m pytest tests/test_report.py`.

## Non-goals

LLMs, txid or address lookups, explorer APIs, Tor, caching, xpub or watch-only
import, signing, broadcasting, keys, custody, multisig, a 0–100 score, and any
"clean/safe/private" label.
