# Sparrow-built test PSBTs

Two sets: `sparrow223_*` (Sparrow 2.2.3, `SparrowPsbt.java`) and `sparrow255_*`
(Sparrow 2.5.5, the latest release on 2026-09-27, `SparrowPsbt255.java`, which
also exports through `getForExport()` like the 2.5.5 menus).
`./generate.sh 2.2.3` or `./generate.sh 2.5.5` rebuilds a set.

`generate.sh` recreates `tests/fixtures/sparrow223_*.psbt` using **Sparrow
Wallet 2.2.3's own code**. This page says exactly what that proves and what it
doesn't.

## How they are made

1. Download the official `sparrowwallet-2.2.3-x86_64.tar.gz` release.
2. Check it: the release manifest must carry a good PGP signature from Craig Raw
   (key `D4D0 D320 2FC0 6849 A257 B38D E946 1833 4C67 4B40`), and the tarball
   must match the SHA-256 listed in that manifest.
3. Run `SparrowPsbt.java` on Sparrow's bundled Java 22 runtime, against the
   `com.sparrowwallet.drongo` module inside the release. drongo is Sparrow's
   wallet library. The driver builds signet wallets from the public BIP39 test
   seed (`abandon … about`, fingerprint `73c5da0a`), gives them made-up confirmed
   coins, and makes the same two calls as Sparrow's Send tab
   (`SendController.createTransaction`):
   - `wallet.createWalletTransaction(...)`, with coin control (`PresetUtxoSelector`);
   - `walletTransaction.createPSBT()`.
4. Export the result the way Sparrow's menus do. **Copy as Base64** is
   `psbt.toBase64String()` and **Save PSBT** is `psbt.serialize()`
   (`AppController.copyPSBT` / `savePSBT`).

The *Finalize Transaction for Signing* button in the GUI only locks the form
(`HeadersController.finalizeTransaction`); it does not change the PSBT. After
**Sign**, Sparrow finalizes a fully signed PSBT (`HeadersController.finalizePSBT`).
The `signed_*` fixtures reproduce both steps.

`javac` here is JDK 21 and drongo is Java 22 bytecode. So, for compiling only,
the script lowers the class-file version on a *copy* of drongo's classes. The
driver then runs on Sparrow's unmodified runtime and classes.

## What this proves

- For these made-up wallets and coins, it's the PSBT content Sparrow 2.2.3's
  code produces: field layout, PSBT
  version (v0), the global xpub, `witness_utxo` together with
  `non_witness_utxo` on segwit v0 inputs, BIP32 and Taproot derivations on
  inputs, derivations on change and self-send outputs, output shuffling,
  nLockTime and nSequence anti-fee-sniping, and what signing and finalizing
  keep.
- LeakCheck parses, normalizes and analyzes all of it as the spec says
  (`tests/test_sparrow.py`).

## What this does NOT prove

- **No PSBT was exported from the Sparrow GUI from a real signet wallet.** The
  coin history is made up, not synced from a server, and wallet settings
  (e.g. PSBT export options) are defaults.
- Hardware-wallet flows beyond the wallet-model flag, multisig, and Sparrow
  versions other than 2.2.3.
- drongo `master` defaults to PSBT **v2** (2.2.3 emits v0). The v2 fixture was
  made with drongo's `convertVersion(2)`; a future Sparrow release may differ.

The real GUI check is still open: see `NOTES.md`.

Output order and Taproot nSequence are random in Sparrow, so a regenerated set
differs byte-for-byte. The tests only assert roles and findings. To run them on
a fresh set:

```sh
LEAKCHECK_SPARROW_FIXTURES=path/to/fixtures python -m pytest tests/test_sparrow.py
```
