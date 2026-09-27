"""PSBT bytes/text -> plain dict of the fields LeakCheck needs.

All serialization is done by embit; nothing is hand-parsed. PSBT_GLOBAL_XPUB
is never read out of the parsed object, so it can't reach the report.
"""

from __future__ import annotations

import base64
import binascii
from typing import Union

from embit.psbt import PSBT

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
        psbt = PSBT.parse(raw)
    except Exception as e:  # embit raises several exception types
        raise LeakCheckError("malformed", f"Malformed PSBT: {e}") from e

    inputs = []
    for i, inp in enumerate(psbt.inputs):
        if inp.non_witness_utxo is not None:
            # A full previous tx is present: it must hash to the txid being
            # spent, or the values it provides can't be trusted.
            try:
                inp.verify()
            except Exception:
                raise LeakCheckError(
                    "utxo_mismatch",
                    f"Input {i}: the included previous transaction does not match "
                    "the coin being spent. Refusing to trust its values.")
        utxo = inp.utxo
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
    for out in psbt.outputs:
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
