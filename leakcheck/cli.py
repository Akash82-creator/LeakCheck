"""Command line. Makes no network requests (except `serve`, which only
listens on 127.0.0.1).

  leakcheck tx.psbt                    text report (or pipe base64/hex on stdin)
  leakcheck tx.psbt --html report.html standalone HTML report file
  leakcheck tx.psbt --json             findings as JSON
  leakcheck serve [--port N] [--demo]  local web UI
  leakcheck open                       local web UI, opened in your browser
"""

import json
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


USAGE = ("usage: leakcheck [FILE] [--html OUT | --json]\n"
         "       leakcheck serve [--port N] [--demo]\n"
         "       leakcheck open")


def _serve(args, open_browser=False) -> int:
    from .server import DEFAULT_PORT, serve
    port, demo = DEFAULT_PORT, False
    it = iter(args)
    for a in it:
        if a == "--demo":
            demo = True
        elif a == "--port":
            try:
                port = int(next(it))
            except (StopIteration, ValueError):
                print(USAGE, file=sys.stderr)
                return 2
        else:
            print(USAGE, file=sys.stderr)
            return 2
    serve(port=port, demo=demo, open_browser=open_browser)
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ["serve"]:
        return _serve(argv[1:])
    if argv[:1] == ["open"]:
        return _serve(argv[1:], open_browser=True)
    html_out, as_json = None, False
    if "--json" in argv:
        argv.remove("--json")
        as_json = True
    if "--html" in argv:
        k = argv.index("--html")
        if k + 1 >= len(argv):
            print(USAGE, file=sys.stderr)
            return 2
        html_out = argv[k + 1]
        del argv[k:k + 2]
    if any(a.startswith("-") for a in argv) or len(argv) > 1 or (html_out and as_json):
        print(USAGE, file=sys.stderr)
        return 2
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
    report, fp = analyze(ntx), panel(ntx)
    if html_out:
        from importlib import resources
        from .report import render_fragment, render_page
        css = resources.files("leakcheck").joinpath("static", "style.css").read_text()
        try:
            with open(html_out, "w", encoding="utf-8") as fh:
                fh.write(render_page(render_fragment(report, fp), css))
        except OSError as e:
            print(f"ERROR (io): cannot write {html_out!r}: {e.strerror}", file=sys.stderr)
            return 2
        print(f"Report written to {html_out}. It describes your transaction; keep it private.")
        return 0
    try:
        if as_json:
            print(json.dumps({"notices": report.notices, "counts": report.counts(),
                              "findings": [f.as_dict() for f in report.findings],
                              "fingerprint": fp, "not_checked": report.not_checked},
                             indent=2))
        else:
            print(render(report, fp))
    except BrokenPipeError:                     # e.g. piped into `head`
        sys.stderr.close()
    return 0


def entry() -> None:
    sys.exit(main())


if __name__ == "__main__":
    entry()
