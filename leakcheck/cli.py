"""Debug CLI: python -m leakcheck.cli file.psbt   (or pipe base64 on stdin).
Prints the report as text. Makes no network requests."""

import sys

from .fingerprint import panel
from .model import LeakCheckError
from .normalize import normalize
from .parse import extract
from .rules import analyze
from . import cards


def render(report, fp) -> str:
    lines = []
    for n in report.notices:
        lines.append(f"NOTICE: {n}")
    for f in report.warnings:
        lines.append(f"[WARNING {f.impact}/{f.confidence}] {f.rule}: {f.observation}")
        lines.append(f"    observer: {f.inference}")
        lines.append(f"    action:   {f.action}")
        lines.append(f"    limits:   {f.limits}")
    for f in report.favorables:
        lines.append(f"[FAVORABLE] {f.rule}: {f.observation}")
        lines.append(f"    {f.inference}")
    c = report.counts()
    if not report.warnings:
        lines.append(cards.EMPTY_SUMMARY.format(applied=c["applied"], total=c["total"],
                                                na=c["not_applicable"]))
    else:
        lines.append(f"{c['applied']} of {c['total']} checks applied; "
                     f"{c['not_applicable']} not applicable.")
    lines.append(f"Fingerprint (visible, not fixable here): nVersion={fp['tx_version']} "
                 f"nLockTime={fp['locktime']} RBF={fp['signals_rbf']} "
                 f"PSBT v{fp['psbt_version']}. {fp['note']}")
    lines.append("Not checked:")
    lines += [f"  - {x}" for x in report.not_checked]
    lines.append("Details:")
    for f in report.details:
        tag = "n/a" if not f.applicable else f.kind
        under = f" (under {f.parent})" if f.parent else ""
        lines.append(f"  - {f.rule} [{tag}]{under}: {f.observation}")
    return "\n".join(lines)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        if argv:
            with open(argv[0], "rb") as fh:
                data = fh.read()
        else:
            data = sys.stdin.buffer.read()      # bytes: binary or base64 both work
    except OSError as e:
        print(f"ERROR (io): cannot read {argv[0]!r}: {e.strerror}", file=sys.stderr)
        return 2
    try:
        ntx = normalize(extract(data))
    except LeakCheckError as e:
        print(f"ERROR ({e.code}): {e.message}", file=sys.stderr)
        return 2
    try:
        print(render(analyze(ntx), panel(ntx)))
    except BrokenPipeError:                     # e.g. piped into `head`
        sys.stderr.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
