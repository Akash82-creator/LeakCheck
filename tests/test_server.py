"""Local web UI. Requests use the 127.0.0.1 host, as a browser would."""

import logging

import pytest
from fastapi.testclient import TestClient

import psbt_factory as pf
from leakcheck import server

BASE = "http" + "://127.0.0.1"


@pytest.fixture
def client():
    return TestClient(server.create_app(), base_url=BASE)


@pytest.fixture
def demo():
    return TestClient(server.create_app(demo=True), base_url=BASE)


def test_page_has_strict_csp_and_no_external_assets(client):
    r = client.get("/")
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src 'sha256-" in csp
    assert r.headers["referrer-policy"] == "no-referrer"
    assert 'id="paste"' in r.text and 'id="drop"' in r.text


@pytest.mark.parametrize("encode", [lambda p: p.to_string().encode(), lambda p: p.serialize()])
def test_analyze_base64_and_binary(client, encode):
    r = client.post("/api/analyze", content=encode(pf.standard_payment()))
    assert r.status_code == 200
    assert 'data-rule="common-input-linkage"' in r.text
    assert r.headers["cache-control"] == "no-store"


def test_bad_input_is_a_clean_error(client):
    r = client.post("/api/analyze", content=b"hello")
    assert r.status_code == 400 and 'data-code="not_psbt"' in r.text


def test_oversized_body_rejected(client):
    r = client.post("/api/analyze", content=b"A" * (server.MAX_BODY + 1))
    assert r.status_code == 413


def test_samples(client):
    for name in ("a", "b"):
        assert client.get(f"/api/sample/{name}").status_code == 200
    assert client.get("/api/sample/zzz").status_code == 404


def test_demo_mode_refuses_real_psbts(demo):
    r = demo.post("/api/analyze", content=pf.standard_payment().to_string().encode())
    assert r.status_code == 403
    page = demo.get("/").text
    assert 'id="paste"' not in page and 'data-demo="1"' in page
    assert demo.get("/api/sample/a").status_code == 200


def test_other_host_names_are_refused():
    c = TestClient(server.create_app(), base_url="http" + "://evil.example")
    assert c.get("/").status_code == 400


def test_psbt_is_not_logged(client, caplog):
    text = pf.standard_payment().to_string()
    with caplog.at_level(logging.DEBUG):
        client.post("/api/analyze", content=text.encode())
    assert text[:40] not in caplog.text


def test_unexpected_error_is_not_logged(client, caplog, monkeypatch):
    secret = "cHNidP8BAHECAAAAAQ-psbt-that-must-not-be-logged"

    def boom(data):
        raise ValueError(secret)
    monkeypatch.setattr(server, "check", boom)
    with caplog.at_level(logging.DEBUG):
        r = client.post("/api/analyze", content=secret.encode())
    assert r.status_code == 500 and 'data-code="internal"' in r.text
    assert secret not in caplog.text and secret not in r.text


# ------------------------------------------------ request size, at ASGI level
# TestClient reads a streamed body completely before the app sees it, so these
# drive the ASGI app directly and count how many body chunks it pulls.

CHUNK = 64 * 1024


def _asgi_post(app, n_chunks, chunk=b"A" * CHUNK, headers=()):
    import asyncio
    pulled, messages = 0, []

    async def receive():
        nonlocal pulled
        if pulled < n_chunks:
            pulled += 1
            return {"type": "http.request", "body": chunk if isinstance(chunk, bytes)
                    else chunk[pulled - 1], "more_body": pulled < n_chunks}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": "POST", "scheme": "http", "path": "/api/analyze",
             "raw_path": b"/api/analyze", "query_string": b"", "root_path": "",
             "headers": [(b"host", b"127.0.0.1"), *headers],
             "client": ("127.0.0.1", 50000), "server": ("127.0.0.1", 8765)}
    asyncio.run(app(scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return start["status"], pulled, body


def test_oversized_streamed_body_stops_reading_at_the_limit():
    total = 1600                                     # 100 MB offered in 64 KiB chunks
    status, pulled, body = _asgi_post(server.create_app(), total)
    assert status == 413 and b"too_large" in body
    assert pulled <= server.MAX_BODY // CHUNK + 1    # ~16 chunks, not 1,600
    assert pulled < total


def test_declared_oversized_body_is_refused_before_reading():
    status, pulled, _ = _asgi_post(server.create_app(), 1600, headers=[
        (b"content-length", str(1600 * CHUNK).encode())])
    assert status == 413 and pulled == 0


def test_body_exactly_at_the_limit_is_read_and_analyzed_normally():
    status, pulled, body = _asgi_post(server.create_app(), 1, chunk=b"A" * server.MAX_BODY)
    assert status == 400 and b"not_psbt" in body           # read fully, then rejected as not a PSBT


def test_chunked_psbt_is_reassembled():
    data = pf.standard_payment().to_string().encode()
    parts = [data[i:i + 100] for i in range(0, len(data), 100)]
    status, pulled, body = _asgi_post(server.create_app(), len(parts), chunk=parts)
    assert status == 200 and pulled == len(parts)
    assert b'data-rule="common-input-linkage"' in body
