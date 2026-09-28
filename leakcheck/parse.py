"""PSBT bytes/text -> plain dict of the fields LeakCheck needs.

All serialization is done by embit; nothing is hand-parsed. PSBT_GLOBAL_XPUB
is never read out of the parsed object, so it can't reach the report.
"""

from __future__ import annotations

import base64
import binascii
from io import BytesIO
from typing import Union

from embit import compact
from embit import script as escript
from embit.psbt import PSBT, InputScope, OutputScope, PSBTError, read_string

from .model import LeakCheckError

MAGIC = b"psbt\xff"


def decode(data: Union[bytes, str]) -> bytes:
    """Accept raw PSBT bytes, or text holding base64 (Sparrow's copy format) or hex.
    Bytes that are themselves base64 text (a .psbt file saved as text) work too."""
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data)
        if data.startswith(MAGIC):
            return data
        try:
            data = data.decode("ascii")
        except UnicodeDecodeError:
            raise LeakCheckError("not_psbt", "This file is not a PSBT.")
    text = "".join(data.split()).strip("\"'")      # tolerate pasted quotes
    if text[:10].lower() == MAGIC.hex():               # hex text, "70736274ff..."
        try:
            return bytes.fromhex(text)
        except ValueError:
            raise LeakCheckError("not_psbt", "Could not read this as a hex PSBT.")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise LeakCheckError("not_psbt", "Could not read this as a base64 PSBT.")
    if not raw.startswith(MAGIC):
        raise LeakCheckError("not_psbt", "This is not a PSBT (missing the 'psbt' header).")
    return raw


def _checked_tap_derivation(stream) -> BytesIO:
    """embit 0.8.0 loops over a Taproot derivation's leaf-hash count without
    checking it against the field's length, so a few crafted bytes can exhaust
    memory. Check the count first, then hand embit the unchanged bytes."""
    value = read_string(stream)
    count = compact.read_from(BytesIO(value))
    if count * 32 > len(value):
        raise PSBTError("Invalid number of taproot leaf hashes")
    return BytesIO(compact.to_bytes(len(value)) + value)


def _no_duplicate(scope, k):
    """BIP174: a key may appear at most once per map. embit only checks some keys."""
    if k:
        seen = scope.__dict__.setdefault("_leakcheck_keys", set())
        if k in seen:
            raise PSBTError("Duplicated key in a PSBT map")
        seen.add(k)


class _InputScope(InputScope):
    def read_value(self, stream, k):
        _no_duplicate(self, k)
        if k and k[0] == 0x16:                       # PSBT_IN_TAP_BIP32_DERIVATION
            stream = _checked_tap_derivation(stream)
        return super().read_value(stream, k)


class _OutputScope(OutputScope):
    def read_value(self, stream, k):
        _no_duplicate(self, k)
        if k and k[0] == 0x07:                       # PSBT_OUT_TAP_BIP32_DERIVATION
            stream = _checked_tap_derivation(stream)
        return super().read_value(stream, k)


# More inputs or outputs than any standard transaction can hold (400,000
# weight units allow at most ~2,439 inputs or ~11,111 outputs).
MAX_SCOPES = 20_000


class _PSBT(PSBT):
    PSBTIN_CLS = _InputScope
    PSBTOUT_CLS = _OutputScope

    def parse_unknowns(self):
        """embit 0.8.0 allocates one object per declared PSBTv2 input/output
        (PSBT_GLOBAL_INPUT_COUNT / OUTPUT_COUNT) before reading any, so a huge
        count exhausts memory. Reject impossible counts first."""
        g = self.unknown
        if self.version not in (None, 0, 2):
            raise PSBTError(f"Unsupported PSBT version {self.version}")
        v2_only = [k for k in (b"\x02", b"\x03", b"\x04", b"\x05") if k in g]
        if self.version != 2:
            if v2_only:
                raise PSBTError("PSBTv2-only global fields in a v0 PSBT")
        else:
            # BIP370: TX_VERSION, INPUT_COUNT and OUTPUT_COUNT are required.
            for k, name in ((b"\x02", "TX_VERSION"), (b"\x04", "INPUT_COUNT"),
                            (b"\x05", "OUTPUT_COUNT")):
                if k not in g:
                    raise PSBTError(f"PSBTv2 is missing PSBT_GLOBAL_{name}")
            for k in (b"\x02", b"\x03"):
                if k in g and len(g[k]) != 4:
                    raise PSBTError("PSBTv2 version and lock time fields must be 4 bytes")
        for key in (b"\x04", b"\x05"):
            if key in g and compact.from_bytes(g[key]) > MAX_SCOPES:
                raise PSBTError("Too many inputs or outputs declared")
        super().parse_unknowns()


def _utxo(i: int, inp):
    """The coin an input spends. When the full previous transaction is
    included, it must hash to the txid being spent, and the output it provides
    is the one used. A witness_utxo that disagrees with it is rejected, never
    silently preferred (embit's `utxo` property would prefer it)."""
    if inp.non_witness_utxo is None:
        return inp.witness_utxo
    try:
        inp.verify()
    except Exception:
        raise LeakCheckError(
            "utxo_mismatch",
            f"Input {i}: the included previous transaction does not match "
            "the coin being spent. Refusing to trust its values.")
    prev_outputs = inp.non_witness_utxo.vout
    if not 0 <= inp.vout < len(prev_outputs):
        raise LeakCheckError(
            "utxo_mismatch",
            f"Input {i} spends output {inp.vout}, which its previous transaction "
            "doesn't have.")
    utxo = prev_outputs[inp.vout]
    w = inp.witness_utxo
    if w is not None and (w.value != utxo.value or
                          bytes(w.script_pubkey.data) != bytes(utxo.script_pubkey.data)):
        raise LeakCheckError(
            "utxo_mismatch",
            f"Input {i}: the two copies of the coin being spent (witness_utxo and "
            "the previous transaction) disagree. Refusing to trust either.")
    return utxo


def _key_fits(spk: bytes, pub, tap_leaves=None, tweaked=False):
    """Does this derivation's public key produce the script it is attached to?
    True/False for single-key scripts; None when that can't be checked here
    (script-hash scripts other than P2SH-P2WPKH, Taproot script paths or a
    script tree, anything else). Only the key is checked: without the xpub,
    the fingerprint and path themselves can't be re-derived."""
    try:
        if spk[:1] == b"\x76" and len(spk) == 25:                       # p2pkh
            return escript.p2pkh(pub).data == spk
        if spk[:2] == b"\x00\x14" and len(spk) == 22:                   # p2wpkh
            return escript.p2wpkh(pub).data == spk
        if spk[:2] == b"\xa9\x14" and len(spk) == 23:                   # p2sh
            return True if escript.p2sh(escript.p2wpkh(pub)).data == spk else None
        if spk[:2] == b"\x51\x20" and len(spk) == 34:                   # p2tr
            if tap_leaves or tweaked:
                return None
            return escript.p2tr(pub).data == spk
    except Exception:
        return None
    return None


def _bad_derivations(scope, spk: bytes, taproot_tree: bool) -> list:
    """(fingerprint, path) of derivations whose key provably doesn't fit."""
    bad = []
    for pub, der in scope.bip32_derivations.items():
        if _key_fits(spk, pub) is False:
            bad.append((int.from_bytes(bytes(der.fingerprint), "big"), tuple(der.derivation)))
    for pub, (leaves, der) in scope.taproot_bip32_derivations.items():
        if _key_fits(spk, pub, leaves, taproot_tree) is False:
            bad.append((int.from_bytes(bytes(der.fingerprint), "big"), tuple(der.derivation)))
    return bad


def _derivations(scope) -> list:
    """(fingerprint_int, path_tuple) for every BIP32 and Taproot derivation."""
    out = []
    for der in scope.bip32_derivations.values():
        out.append((int.from_bytes(bytes(der.fingerprint), "big"), tuple(der.derivation)))
    for _leaf_hashes, der in scope.taproot_bip32_derivations.values():
        out.append((int.from_bytes(bytes(der.fingerprint), "big"), tuple(der.derivation)))
    return out


def extract(data: Union[bytes, str]) -> dict:
    raw = decode(data)
    try:
        psbt = _PSBT.parse(raw)
    except Exception as e:  # embit raises several exception types
        raise LeakCheckError("malformed", f"Malformed PSBT: {e}") from e
    try:
        return _fields(psbt)
    except LeakCheckError:
        raise
    except PSBTError as e:
        raise LeakCheckError("malformed", f"Malformed PSBT: {e}") from e
    except Exception as e:  # fields embit accepted but that don't make sense
        raise LeakCheckError("malformed", f"Malformed PSBT: {type(e).__name__}") from e


def _locktime(psbt) -> int:
    """nLockTime as BIP370 determines it. v0: the unsigned tx's. v2: if inputs
    require a lock time (PSBT_IN_REQUIRED_TIME/HEIGHT_LOCKTIME), the maximum of
    the type every such input supports (height if both); else the fallback."""
    if psbt.version != 2:
        return psbt.locktime
    times, heights, any_required = [], [], False
    both_ok = time_ok = height_ok = True
    for inp in psbt.inputs:
        t, h = inp.unknown.get(b"\x11"), inp.unknown.get(b"\x12")
        for v in (t, h):
            if v is not None and len(v) != 4:
                raise PSBTError("Required lock time fields must be 4 bytes")
        if t is None and h is None:
            continue
        any_required = True
        time_ok &= t is not None
        height_ok &= h is not None
        if t is not None:
            times.append(int.from_bytes(t, "little"))
        if h is not None:
            heights.append(int.from_bytes(h, "little"))
    if not any_required:
        return psbt.locktime if psbt.locktime is not None else 0
    if height_ok:
        return max(heights)
    if time_ok:
        return max(times)
    raise PSBTError("Inputs require incompatible lock time types")


def _fields(psbt) -> dict:
    if psbt.version == 2:
        for i, inp in enumerate(psbt.inputs):
            if inp.txid is None or inp.vout is None:
                raise LeakCheckError("malformed", f"Malformed PSBT: PSBTv2 input {i} lacks "
                                     "its previous txid or output index.")
    inputs = []
    for i, inp in enumerate(psbt.inputs):
        utxo = _utxo(i, inp)
        if utxo is None:
            raise LeakCheckError(
                "missing_utxo",
                f"Input {i} has no UTXO data, so its value is unknown. "
                "LeakCheck never guesses values.")
        spk = bytes(utxo.script_pubkey.data)
        inputs.append({
            "bad_derivations": _bad_derivations(inp, spk, inp.taproot_merkle_root is not None),
            "txid": bytes(inp.txid).hex(),
            "vout": inp.vout,
            "value": int(utxo.value),
            "spk": bytes(utxo.script_pubkey.data).hex(),
            "sequence": inp.sequence if inp.sequence is not None else 0xFFFFFFFF,
            "derivations": _derivations(inp),
            "finalized": inp.final_scriptwitness is not None or inp.final_scriptsig is not None,
        })

    outputs = []
    for n, out in enumerate(psbt.outputs):
        if b"\x09" in out.unknown or b"\x0a" in out.unknown:   # PSBT_OUT_SP_V0_INFO / _LABEL
            # BIP375 Silent Payments: the script may not exist yet, and a
            # Silent Payments change output carries no BIP32 derivation, so it
            # would look like a payment. Not supported rather than misread.
            raise LeakCheckError(
                "unsupported",
                f"Output {n} is a Silent Payments output (BIP375). LeakCheck "
                "doesn't support Silent Payments yet.")
        if out.value is None or out.script_pubkey is None:
            raise LeakCheckError("malformed", f"Malformed PSBT: output {n} has no "
                                 "amount or no script.")
        spk = bytes(out.script_pubkey.data)
        tree = b"\x06" in out.unknown or getattr(out, "taproot_tree", None) is not None
        outputs.append({
            "bad_derivations": _bad_derivations(out, spk, tree),
            "value": int(out.value),
            "spk": bytes(out.script_pubkey.data).hex(),
            "derivations": _derivations(out),
        })

    return {
        "psbt_version": psbt.version,
        # v0: from the unsigned tx. v2: TX_VERSION is required (checked above).
        "tx_version": psbt.tx_version,
        "locktime": _locktime(psbt),
        "inputs": inputs,
        "outputs": outputs,
    }
