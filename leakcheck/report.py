"""Report rendering: Report + fingerprint panel -> HTML. No I/O.

One renderer serves both the local web UI (as a fragment) and the static
`--html` file (as a full page), so the two can never disagree. Every value
is escaped. The output must contain no URLs of any kind (a test scans it).

Layout (spec §2): notices, summary, warnings, favorable findings,
fingerprint panel, "not checked" list, then Details (collapsed).
"""

from __future__ import annotations

from html import escape
from typing import List, Tuple, Union

from . import cards
from .fingerprint import panel
from .model import Finding, LeakCheckError, Report
from .normalize import normalize
from .parse import extract
from .rules import analyze

TITLES = {
    "common-input-linkage": "Your inputs are linked to each other",
    "foreign-input": "An input carries another wallet's fingerprint",
    "input-address-reuse": "An address you spend from was funded more than once",
    "sender-reuse": "An output goes back to an address you already use",
    "recipient-reuse": "A recipient address is used more than once",
    "consolidation": "Several coins merge into one output of yours",
    "self-transfer": "Every output returns to this wallet",
    "small-input": "A small coin is spent together with your others",
    "changeless": "No change output",
    "round-payment": "Round-amount heuristic",
    "script-type-match": "Script-type heuristic",
    "optimal-change": "Optimal-change heuristic",
    "change-verdict": "An observer could identify your change",
}
VERDICT_TITLES = {
    "warning": "An observer could identify your change",
    "favorable": "An observer would likely misidentify your change",
    "neutral": "Change output: ambiguous under these checks",
}
KIND_LABEL = {"warning": "Warning", "favorable": "Favorable", "neutral": "Neutral"}


def check(data: Union[bytes, str]) -> Tuple[Report, dict]:
    """The whole local pipeline. Raises LeakCheckError on rejected input."""
    ntx = normalize(extract(data))
    return analyze(ntx), panel(ntx)


def _title(f: Finding) -> str:
    if f.rule == "change-verdict":
        return VERDICT_TITLES[f.kind]
    return TITLES.get(f.rule, f.rule)


def summary(report: Report) -> str:
    c = report.counts()
    if not report.warnings:
        return cards.EMPTY_SUMMARY.format(applied=c["applied"], total=c["total"],
                                          na=c["not_applicable"])
    w, fav = len(report.warnings), len(report.favorables)
    return (f"{c['applied']} of {c['total']} checks applied to this transaction; "
            f"{w} warning{'s' if w != 1 else ''}, {fav} favorable "
            f"finding{'s' if fav != 1 else ''}; {c['not_applicable']} not applicable "
            "(see Details).")


def _action(text: str) -> str:
    """The action text without the 'Limited: ' marker (shown as a tag instead)."""
    if text.startswith(cards.LIMITED):
        text = text[len(cards.LIMITED):]
        text = text[:1].upper() + text[1:]
    return text


def _card(f: Finding, evidence: List[Finding]) -> str:
    e = escape
    meta = []
    if f.impact:
        meta.append(f"impact: {e(f.impact)}")
    if f.confidence:
        meta.append(f"confidence: {e(f.confidence)}")
    fixable = ""
    if f.kind == "warning":
        # Every change heuristic's fix is limited (the recipient sets amount and
        # address type), so the verdict built from them is limited too.
        limited = f.action.startswith(cards.LIMITED) or f.rule == "change-verdict"
        fixable = (f'<span class="tag {"limited" if limited else "fixable"}">'
                   f'{"Limited" if limited else "Fixable before broadcast"}</span>')
    action = _action(f.action)
    if f.rule == "change-verdict":
        meta.append("combined verdict of the change heuristics below; "
                    "not counted as a separate check")
    parts = [
        f'<article class="card {e(f.kind)}" data-rule="{e(f.rule)}">',
        f'<header><span class="badge">{KIND_LABEL[f.kind]}</span>'
        f'<h3>{e(_title(f))}</h3>{fixable}</header>',
        f'<p class="meta"><code>{e(f.rule)}</code>'
        + "".join(f" &middot; {m}" for m in meta) + "</p>",
        f'<p class="obs">{e(f.observation)}</p>',
        "<dl>",
        f"<dt>What an observer concludes</dt><dd>{e(f.inference)}</dd>",
        f"<dt>What you can still change</dt><dd>{e(action)}</dd>",
        f"<dt>Limits</dt><dd>{e(f.limits)}</dd>",
        "</dl>",
    ]
    if evidence:
        parts.append('<div class="evidence"><h4>Evidence: the individual change heuristics</h4><ul>')
        for ev in evidence:
            extra = ""
            if ev.kind == "warning":
                extra = (f'<br><span class="muted">{e(ev.inference)} '
                         f'{e(_action(ev.action))}</span>')
            parts.append(f'<li class="{e(ev.kind)}"><code>{e(ev.rule)}</code> '
                         f'[{e(KIND_LABEL[ev.kind].lower())}]: {e(ev.observation)}{extra}</li>')
        parts.append("</ul></div>")
    parts.append("</article>")
    return "".join(parts)


def _fingerprint(fp: dict) -> str:
    e = escape
    rows = [("nVersion", str(fp["tx_version"])), ("nLockTime", str(fp["locktime"]))]
    for n, s in enumerate(fp["sequences"]):
        rbf = " (signals RBF)" if int(s, 16) < 0xFFFFFFFE else ""
        rows.append((f"nSequence, input {n}", s + rbf))
    body = "".join(f"<tr><th>{e(k)}</th><td><code>{e(v)}</code></td></tr>" for k, v in rows)
    return ('<section class="fingerprint"><h2>Transaction fingerprint signals: visible, '
            'not fixable in this transaction</h2>'
            '<p class="muted">Fields of the transaction itself that anyone can read on-chain. '
            "Not related to your wallet's master key fingerprint.</p>"
            f'<table>{body}</table><p>{e(fp["note"])}</p>'
            f'<p class="muted">PSBT version: v{e(str(fp["psbt_version"]))} (the file format '
            'only; it is never broadcast, so observers never see it).</p></section>')


def _details(report: Report, shown_evidence: set) -> str:
    e = escape
    items = []
    for f in report.details:
        if id(f) in shown_evidence:
            continue
        tag = "not applicable" if not f.applicable else KIND_LABEL[f.kind].lower()
        items.append(f'<li><code>{e(f.rule)}</code> [{e(tag)}]: {e(f.observation)}'
                     f'<br><span class="muted">{e(f.limits)}</span></li>')
    return (f'<details class="details"><summary>Details ({len(items)})</summary>'
            f'<ul>{"".join(items)}</ul></details>')


def render_fragment(report: Report, fp: dict) -> str:
    e = escape
    evidence = [f for f in report.findings if f.parent == "change-verdict"]
    verdict = report.by_rule("change-verdict")
    shown = set()
    out = ['<div class="report">']
    for n in report.notices:
        out.append(f'<p class="notice">{e(n)}</p>')
    out.append(f'<p class="summary">{e(summary(report))}</p>')

    def section(title, findings, cls):
        if not findings:
            return
        out.append(f'<section class="{cls}"><h2>{title} ({len(findings)})</h2>')
        for f in findings:
            ev = evidence if f is verdict else []
            shown.update(map(id, ev))
            out.append(_card(f, ev))
        out.append("</section>")

    section("Warnings", report.warnings, "warnings")
    section("Favorable findings", report.favorables, "favorables")
    out.append(_fingerprint(fp))
    out.append('<section class="not-checked"><h2>Not checked</h2><ul>'
               + "".join(f"<li>{e(x)}</li>" for x in report.not_checked) + "</ul></section>")
    out.append(_details(report, shown))
    out.append("</div>")
    return "\n".join(out)


def render_error(err: LeakCheckError) -> str:
    return (f'<div class="report"><p class="error" data-code="{escape(err.code)}">'
            f"<strong>Could not check this PSBT.</strong> {escape(err.message)}</p></div>")


def render_page(fragment: str, css: str) -> str:
    """A standalone report file: inline CSS, no script, no external anything."""
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<meta http-equiv=\"Content-Security-Policy\" "
            "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            "<meta name=\"referrer\" content=\"no-referrer\">"
            "<title>LeakCheck report</title>"
            f"<style>{css}</style></head><body><main>"
            "<h1>LeakCheck report</h1>"
            "<p class=\"muted\">Generated locally. This file describes your transaction; "
            "treat it as private.</p>"
            f"{fragment}</main></body></html>\n")
