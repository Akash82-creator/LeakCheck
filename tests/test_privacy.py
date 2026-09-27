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
