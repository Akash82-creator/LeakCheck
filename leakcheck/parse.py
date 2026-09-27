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


class _InputScope(InputScope):
    def read_value(self, stream, k):
        if k and k[0] == 0x16:                       # PSBT_IN_TAP_BIP32_DERIVATION
            stream = _checked_tap_derivation(stream)
        return super().read_value(stream, k)


class _OutputScope(OutputScope):
    def read_value(self, stream, k):
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
        for key in (b"\x04", b"\x05"):
            if key in self.unknown and compact.from_bytes(self.unknown[key]) > MAX_SCOPES:
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
    except Exception as e:  # fields embit accepted but that don't make sense
        raise LeakCheckError("malformed", f"Malformed PSBT: {type(e).__name__}") from e


def _fields(psbt) -> dict:
    inputs = []
    for i, inp in enumerate(psbt.inputs):
        utxo = _utxo(i, inp)
        if utxo is None:
            raise LeakCheckError(
                "missing_utxo",
                f"Input {i} has no UTXO data, so its value is unknown. "
                "LeakCheck never guesses values.")
        inputs.append({
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
        if out.value is None or out.script_pubkey is None:
            raise LeakCheckError("malformed", f"Malformed PSBT: output {n} has no "
                                 "amount or no script.")
        outputs.append({
            "value": int(out.value),
            "spk": bytes(out.script_pubkey.data).hex(),
            "derivations": _derivations(out),
        })

    return {
        "psbt_version": psbt.version,
        # BIP370 defaults when a v2 PSBT omits these fields
        "tx_version": psbt.tx_version if psbt.tx_version is not None else 2,
        "locktime": psbt.locktime if psbt.locktime is not None else 0,
        "inputs": inputs,
        "outputs": outputs,
    }
