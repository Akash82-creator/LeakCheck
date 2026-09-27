"""The double-click path: `leakcheck open`, port choice, and browser opening."""

import os
import pathlib
import socket

import pytest

from leakcheck import cli, server

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _listening():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    return s


def test_pick_port_prefers_the_default_when_free():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free = probe.getsockname()[1]
    assert server.pick_port(free) == free


def test_pick_port_falls_back_when_taken():
    with _listening() as busy:
        taken = busy.getsockname()[1]
        port = server.pick_port(taken)
    assert port != taken and port > 0


def test_browser_opens_the_loopback_page_once_the_server_is_up():
    opened = []
    with _listening() as s:
        port = s.getsockname()[1]
        assert server.open_when_ready(port, timeout=2, opener=opened.append)
    assert opened == ["http" + f"://127.0.0.1:{port}/"]


def test_browser_is_not_opened_if_the_server_never_starts():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    opened = []
    assert not server.open_when_ready(port, timeout=0.3, opener=opened.append)
    assert opened == []


def test_open_command_serves_with_browser(monkeypatch):
    seen = {}
    monkeypatch.setattr(server, "serve", lambda **kw: seen.update(kw))
    assert cli.main(["open"]) == 0
    assert seen == {"port": server.DEFAULT_PORT, "demo": False, "open_browser": True}


def test_serve_with_browser_stays_on_loopback(monkeypatch):
    import uvicorn
    seen, started = {}, []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    monkeypatch.setattr(server, "open_when_ready", lambda port: started.append(port))
    server.serve(port=0, open_browser=True)
    assert seen["host"] == "127.0.0.1" and seen["access_log"] is False
    assert seen["port"] > 0


@pytest.mark.parametrize("name", ["LeakCheck-mac.command", "LeakCheck-linux.sh",
                                  "scripts/launch.sh"])
def test_unix_launchers_are_executable(name):
    assert os.access(ROOT / name, os.X_OK)


def test_launchers_start_the_open_command():
    assert "-m leakcheck open" in (ROOT / "scripts" / "launch.sh").read_text()
    assert "-m leakcheck open" in (ROOT / "LeakCheck-windows.bat").read_text()
