# NOTES: Day-0 checks (spec §11) and validation status

## Validation status

| What | Status |
|---|---|
| Synthetic fixtures (hand-built dicts and embit-built PSBTs) | **Tested.** Every rule, precedence step, the verdict truth table, degraded mode. |
| PSBTs built by **Sparrow 2.2.3's own code** (signed release, driven headlessly, made-up coin history; see `scripts/sparrow/README.md`) | **Tested.** 13 cases: P2WPKH, P2SH-P2WPKH, Taproot, PSBT v0 (and v2 made with drongo's `convertVersion(2)`; 2.2.3 itself emits v0), base64 and binary, a hardware-wallet model flag (no difference seen: all segwit v0 cases carried both UTXO copies), self-send, send-max, batch, signed, signed-and-finalized (`tests/test_sparrow.py`). |
| A PSBT **exported from the Sparrow GUI** from a real signet wallet | **Pending.** Not done: no signet wallet or GUI was available in the build environment. |
| Other wallets (Bitcoin Core, Electrum, hardware wallets, PayJoin receivers) | **Not tested.** |

To close the pending row: in Sparrow (signet), build demo A and demo B,
click *Finalize Transaction for Signing*, then use Sparrow's "Copy as Base64"
command (the source names it `copyPSBTBase64`; its exact menu location is
UNVERIFIED) or **Save PSBT** for the binary form, and run
`python -m leakcheck file.psbt`. With the same amounts and coin choices (A: 80,000
+ 70,000 + 600 sats paying 100,000; B: one 200,000-sat coin paying 100,000), the
findings should match `tests/test_sparrow.py`. Real fees and output order will differ.

## Day-0 checks

| # | Check | Status |
|---|---|---|
| 1 | Deadline date, time, timezone, submission requirements | **Open.** The overview (boss-battle.devfolio.co) says the event ends Mon Oct 5, 2026; the exact cutoff time and timezone are still unverified. |
| 2 | Library parses a Sparrow signet PSBT offline, incl. Taproot | **Done for Sparrow 2.2.3's code; GUI export pending.** `embit==0.8.0` parses them offline, including Taproot (`TAP_BIP32_DERIVATION` + internal key). Sparrow 2.2.3 emits **PSBT v0**; drongo `master` defaults to **v2**, which also parses (tested via `convertVersion(2)`). |
| 3 | Sparrow PSBT has input UTXO data and change-output derivations | **Yes in Sparrow 2.2.3's code; GUI export pending.** Segwit v0 inputs carry `witness_utxo` *and* `non_witness_utxo`; Taproot inputs carry `witness_utxo`. Change (`…/1/i`) and self-send (`…/0/i`) outputs carry derivations, so degraded mode is not the default. Exception: a changeless payment (send max) has no owned output and always shows the degraded notice (spec §5, known consequence). |
| 4 | Sparrow on signet; faucet works; coins requested | **Open.** |
| 5 | Sparrow exports copyable base64 | **In the 2.2.3 source** (`AppController.copyPSBTBase64` → `toBase64String()`); not tried in the GUI. |
| 6 | Prior art search | **Open.** No prior-art claims until done. |
| 7 | BIP78: do receivers add derivations to their inputs? | **Open, non-blocking.** Precedence step 5 handles both cases. |

## Other facts learned from Sparrow 2.2.3

- Every PSBT includes one `PSBT_GLOBAL_XPUB`. embit parses it; LeakCheck never
  uses or displays it, and tests check it never reaches the report.
- Signing then finalizing in Sparrow **keeps** the derivation paths, so a PSBT
  exported after signing is still accepted. Wallets that strip them get
  `finalized_no_metadata`.
- Output order is shuffled (`SecureRandom`). nLockTime is set to the current
  height; on Taproot, Sparrow sometimes uses nSequence-based anti-fee-sniping
  instead (nLockTime 0).
- Sparrow's QR export leaves out `non_witness_utxo` for segwit wallets;
  `witness_utxo` is still there, so this doesn't affect LeakCheck.

## Robustness (fuzzing)

Mutating the Sparrow-built PSBTs 20,000 times turned up two crash types (an
output without amount or script) and one memory exhaustion (Taproot leaf-hash
count). Code review found two more (an unchecked `witness_utxo`, an out-of-range
vout). After those fixes, 60,000 further mutations produced no exception other
than a clean `LeakCheckError`, and none took more than 0.5 s. Random fuzzing
still missed a second memory exhaustion (PSBTv2 input/output counts), found
later by reading embit's code; see `CHANGELOG.md`. Fuzzing is evidence, not proof.
A fast deterministic slice runs in the test suite
(`test_mutated_psbts_only_ever_raise_leakcheck_errors`).

## Demo samples

`leakcheck/samples/demo_{a,b}.psbt` are copies of
`tests/fixtures/sparrow223_p2wpkh_demo_{a,b}.psbt`: built by Sparrow 2.2.3's
code, not exported from the GUI. They replaced the earlier synthetic samples
(same findings). Before recording, swap in GUI exports and refresh the golden
snapshots.
