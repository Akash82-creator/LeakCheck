"""End-to-end: the real CLI in a subprocess, the way a user runs it."""

import os
import subprocess
import sys

import pytest

import psbt_factory as pf

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cli(*args, stdin=None):
    return subprocess.run([sys.executable, "-m", "leakcheck.cli", *args], cwd=ROOT,
                          input=stdin, capture_output=True)


@pytest.fixture
def psbt():
    return pf.standard_payment()


def test_file_base64(tmp_path, psbt):
    f = tmp_path / "a.psbt"
    f.write_text(psbt.to_string())
    r = cli(str(f))
    assert r.returncode == 0 and b"change-verdict" in r.stdout and not r.stderr


@pytest.mark.parametrize("encode", [
    lambda p: p.serialize(),                                   # binary
    lambda p: p.to_string().encode(),                          # base64
    lambda p: p.serialize().hex().encode(),                    # hex
    lambda p: ('"' + p.to_string() + '"').encode(),            # pasted with quotes
    lambda p: "\n".join(p.to_string()[i:i + 64]                # wrapped lines
                        for i in range(0, len(p.to_string()), 64)).encode(),
])
def test_stdin_formats(psbt, encode):
    r = cli(stdin=encode(psbt))
    assert r.returncode == 0, r.stderr
    assert b"common-input-linkage" in r.stdout


@pytest.mark.parametrize("target", ["does-not-exist.psbt", "."])
def test_unreadable_path_is_a_clean_error(target):
    r = cli(target)
    assert r.returncode == 2
    assert r.stderr.startswith(b"ERROR (io)") and b"Traceback" not in r.stderr


@pytest.mark.parametrize("data,code", [(b"", b"not_psbt"), (bytes(range(256)), b"not_psbt"),
                                       (b"hello world", b"not_psbt")])
def test_bad_input_is_a_clean_error(data, code):
    r = cli(stdin=data)
    assert r.returncode == 2 and code in r.stderr and b"Traceback" not in r.stderr


def test_html_report_file(tmp_path, psbt):
    f, html = tmp_path / "a.psbt", tmp_path / "r.html"
    f.write_bytes(psbt.serialize())
    r = cli(str(f), "--html", str(html))
    assert r.returncode == 0, r.stderr
    page = html.read_text()
    assert page.startswith("<!doctype html>") and "common-input-linkage" in page
    assert "//" not in page and "<script" not in page


def test_json_output(psbt):
    import json
    r = cli("--json", stdin=psbt.to_string().encode())
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["counts"]["total"] == 12 and data["findings"]


@pytest.mark.parametrize("args", [["--bogus"], ["a", "b"], ["--html"], ["serve", "--nope"]])
def test_bad_arguments(args):
    r = cli(*args)
    assert r.returncode == 2 and b"usage" in r.stderr
