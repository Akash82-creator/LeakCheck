"""The local check must never touch the network (spec §3)."""

import pathlib
import socket

import psbt_factory as pf
from leakcheck.fingerprint import panel
from leakcheck.normalize import normalize
from leakcheck.parse import extract
from leakcheck.rules import analyze

PKG = pathlib.Path(__file__).resolve().parents[1] / "leakcheck"


def test_full_analysis_makes_no_network_calls(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    ntx = normalize(extract(pf.standard_payment("p2tr").to_string()))
    analyze(ntx)
    panel(ntx)


def test_package_source_contains_no_urls():
    for f in PKG.rglob("*"):
        if f.suffix in {".py", ".html", ".js", ".css"}:
            text = f.read_text()
            assert "http://" not in text and "https://" not in text, f.name


def _built_html():
    from leakcheck import server
    from leakcheck.report import check, render_fragment, render_page
    pages = [server.render_app(False)[0], server.render_app(True)[0]]
    css = (PKG / "static" / "style.css").read_text()
    for name in ("a", "b"):
        pages.append(render_page(render_fragment(*check(server.sample_bytes(name))), css))
    return pages


def test_built_html_and_js_contain_no_urls():
    """Spec §10: fail on http://, https:// or even a bare // in what the browser gets."""
    for page in _built_html():
        for needle in ("http://", "https://", "//"):
            assert needle not in page, needle
    for f in (PKG / "static").iterdir():
        assert "//" not in f.read_text(), f.name


def test_server_binds_to_loopback_only(monkeypatch):
    import uvicorn
    from leakcheck import server
    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    server.serve(port=9999)
    assert seen["host"] == "127.0.0.1" and seen["access_log"] is False
