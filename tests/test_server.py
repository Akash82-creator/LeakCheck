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
