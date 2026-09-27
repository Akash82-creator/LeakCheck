"""Local web UI: FastAPI bound to 127.0.0.1 only (spec §3).

- The page is one HTML file with its CSS and JS inlined; a Content-Security-Policy
  pins the exact script and style by hash, so nothing external can load.
- PSBTs are analyzed in memory and never written to disk or logged. The access
  log is off.
- Demo mode (for a hosted demo) refuses user PSBTs and only analyzes the
  bundled signet samples.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import threading
import time
import webbrowser
from importlib import resources

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .model import LeakCheckError
from .report import check, render_error, render_fragment

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_BODY = 1_000_000          # bytes; real PSBTs are far smaller
SAMPLES = {"a": "demo_a.psbt", "b": "demo_b.psbt"}

INPUT_FORM = """<label for="paste"><strong>Paste a PSBT</strong> (base64 or hex)</label>
<textarea id="paste" spellcheck="false" autocomplete="off"
  placeholder="cHNidP8BA..."></textarea>
<div id="drop" class="drop" role="button" tabindex="0">
  or drop a .psbt file here, or click to choose one
  <input id="file" type="file" accept=".psbt,.txt" hidden>
</div>
<div class="row">
  <button id="check">Check before broadcasting</button>
  <button id="clear" class="secondary">Clear</button>
</div>
<p class="privacy">Runs on this computer only. Your PSBT is never sent anywhere,
saved, or logged. Accepts unsigned and partially signed PSBTs.</p>"""

DEMO_NOTE = """<p class="notice">Hosted demo: this page only analyzes the bundled
signet samples. Never paste a real PSBT into a website; run LeakCheck on your
own computer instead.</p>"""


def _static(name: str) -> str:
    return resources.files("leakcheck").joinpath("static", name).read_text()


def sample_bytes(name: str) -> bytes:
    return resources.files("leakcheck").joinpath("samples", SAMPLES[name]).read_bytes()


def _sha256(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


def render_app(demo: bool = False):
    """Returns (page_html, content_security_policy)."""
    css, js = _static("style.css"), _static("app.js")
    page = (_static("index.html")
            .replace("{{STYLE}}", css).replace("{{SCRIPT}}", js)
            .replace("{{DEMO}}", "1" if demo else "0")
            .replace("{{INPUT}}", DEMO_NOTE if demo else INPUT_FORM))
    csp = ("default-src 'none'; "
           f"script-src {_sha256(js)}; style-src {_sha256(css)}; "
           "connect-src 'self'; img-src 'none'; form-action 'none'; "
           "frame-ancestors 'none'; base-uri 'none'")
    return page, csp


def _fragment(data) -> tuple:
    try:
        report, fp = check(data)
    except LeakCheckError as e:
        return render_error(e), 400
    return render_fragment(report, fp), 200


def create_app(demo: bool = False) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    # Refuse requests addressed to any other host name (DNS rebinding).
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[HOST, "localhost"])
    page, csp = render_app(demo)
    common = {"Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
              "Cache-Control": "no-store"}

    @app.get("/", response_class=HTMLResponse)
    def index():
        return HTMLResponse(page, headers={**common, "Content-Security-Policy": csp})

    @app.post("/api/analyze", response_class=HTMLResponse)
    async def analyze_psbt(request: Request):
        if demo:
            err = LeakCheckError("demo_mode", "This hosted demo only analyzes the "
                                 "bundled samples. Run LeakCheck locally to check your own.")
            return HTMLResponse(render_error(err), status_code=403, headers=common)
        body = await request.body()
        if len(body) > MAX_BODY:
            err = LeakCheckError("too_large", "That is far larger than any PSBT.")
            return HTMLResponse(render_error(err), status_code=413, headers=common)
        html, status = _fragment(body)
        return HTMLResponse(html, status_code=status, headers=common)

    @app.get("/api/sample/{name}", response_class=HTMLResponse)
    def sample(name: str):
        if name not in SAMPLES:
            return HTMLResponse(render_error(LeakCheckError("no_sample", "Unknown sample.")),
                                status_code=404, headers=common)
        html, status = _fragment(sample_bytes(name))
        return HTMLResponse(html, status_code=status, headers=common)

    return app


def pick_port(preferred: int = DEFAULT_PORT) -> int:
    """The preferred port if it is free on 127.0.0.1, else any free port."""
    for candidate in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((HOST, candidate))
            except OSError:
                continue
            return sock.getsockname()[1]
    raise OSError("no free local port")


def local_url(port: int) -> str:
    # Only ever the loopback address this process itself is serving.
    return f"http://{HOST}:{port}/"


def open_when_ready(port: int, timeout: float = 15.0, opener=None) -> bool:
    """Open the page in the default browser once the server accepts
    connections on 127.0.0.1. Returns False if it never came up."""
    opener = opener or webbrowser.open
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.1)
    else:
        return False
    opener(local_url(port))
    return True


def serve(port: int = DEFAULT_PORT, demo: bool = False, open_browser: bool = False) -> None:
    import uvicorn
    if open_browser:
        port = pick_port(port)
        threading.Thread(target=open_when_ready, args=(port,), daemon=True).start()
        print(f"LeakCheck is running on this computer only, at {HOST}:{port}.\n"
              "Your browser should open by itself; if not, type that address into it.\n"
              "To stop LeakCheck, close this window (or press Ctrl+C).")
    else:
        print(f"LeakCheck is running locally. Open {HOST}:{port} in your browser. "
              "Press Ctrl+C to stop.")
    # host is fixed: never 0.0.0.0. access_log off: nothing about requests is logged.
    uvicorn.run(create_app(demo), host=HOST, port=port, log_level="warning",
                access_log=False)
