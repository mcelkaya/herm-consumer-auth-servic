"""uvicorn's own error/access lines must not carry PII or OIDC secrets.

Reproduces: prod logged plain uvicorn lines such as
``INFO: 10.0.3.221:58300 - "POST /herm-auth/v1/pii/auth/refresh HTTP/1.1" 200 OK``.
uvicorn installs its own handlers on ``uvicorn``/``uvicorn.error``/``uvicorn.access``
(they never reach setup_logging's redacting root handler), so client IPs, OIDC
query strings (login_hint=<email>, state, verifier, request_id, ...) and
exception text in "Exception in ASGI application" tracebacks went out raw.

The test starts a real uvicorn server with the log config the Dockerfile CMD
passes (uvicorn's default config when there is none) and sends real requests.
"""

import asyncio
import io
import logging
import re
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import uvicorn
from uvicorn.config import LOGGING_CONFIG

import app.main  # noqa: F401  (attaches the health-check filter to uvicorn.access)

REPO_ROOT = Path(__file__).resolve().parents[2]

EMAIL = "jane.doe@uvicorn-example.org"
ENCODED_EMAIL = "jane.doe%40uvicorn-example.org"
VERIFIER = "vRfY7q2LmN9pXc4tB8kW1zH6dJ3sA0eG"  # gitleaks:allow
STATE = "st4te-Qz81LmXr0"
REQUEST_ID = "req-7f3a9c2e51b4"
CHALLENGE = "chAllenge-E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw"  # gitleaks:allow
NONCE = "n0nce-5d1e8b"


def _dockerfile_log_config():
    """The ``--log-config`` file of the Dockerfile CMD, resolved from WORKDIR (/app = repo root)."""
    cmd = (REPO_ROOT / "Dockerfile").read_text().rsplit("\nCMD ", 1)[1]
    match = re.search(r'--log-config["\s,=]+([^"\s,\]]+)', cmd)  # shell or exec form
    if not match:
        return None
    name = match.group(1)
    path = REPO_ROOT / name
    assert path.is_file(), f"{name} is not in the image (COPY . . from repo root)"
    return str(path)


async def _asgi_app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["path"] == "/boom":
        raise RuntimeError(f"boom for {EMAIL}")
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


@pytest.fixture
def uvicorn_output():
    """Run a real uvicorn server with the Dockerfile's log config; yield (base_url, output)."""
    names = ("uvicorn", "uvicorn.error", "uvicorn.access")
    saved = {n: (logging.getLogger(n).handlers[:], logging.getLogger(n).propagate,
                 logging.getLogger(n).level) for n in names}
    stream = io.StringIO()
    with patch.object(sys, "stderr", stream), patch.object(sys, "stdout", stream):
        config = uvicorn.Config(
            _asgi_app,
            host="127.0.0.1",
            port=0,
            log_config=_dockerfile_log_config() or LOGGING_CONFIG,
        )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=lambda: asyncio.run(server.serve()), daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]

    yield f"http://127.0.0.1:{port}", stream

    server.should_exit = True
    thread.join(timeout=10)
    for n, (handlers, propagate, level) in saved.items():
        lg = logging.getLogger(n)
        lg.handlers, lg.propagate, lg.level = handlers, propagate, level


@pytest.mark.unit
def test_uvicorn_access_and_error_lines_are_redacted(uvicorn_output):
    base_url, output = uvicorn_output
    with httpx.Client(base_url=base_url) as client:
        client.get(
            "/herm-auth/v1/oidc/authorize?response_type=code&client_id=partner-app"
            f"&login_hint={ENCODED_EMAIL}&state={STATE}&code_challenge={CHALLENGE}"
            f"&code_challenge_method=S256&nonce={NONCE}"
        )
        client.get(f"/herm-auth/v1/oidc/authorize?login_hint={EMAIL}")
        client.get(f"/herm-auth/v1/oidc/authorize/finish?verifier={VERIFIER}")
        client.get(f"/herm-auth/v1/oidc/consent?request_id={REQUEST_ID}")
        client.post("/herm-auth/v1/pii/auth/refresh")
        client.get("/herm-auth/v1/public/health")
        client.get("/boom")
    time.sleep(0.2)

    out = output.getvalue()
    # The lines are still there and useful.
    assert "/herm-auth/v1/oidc/authorize" in out
    assert "client_id=partner-app" in out
    assert "&state=[redacted]&" in out and "login_hint=[redacted]" in out
    assert "/herm-auth/v1/pii/auth/refresh" in out and "200" in out
    assert "Exception in ASGI application" in out and "Traceback" in out
    # The health-check filter still drops probe noise.
    assert "/herm-auth/v1/public/health" not in out
    # No PII, OIDC secrets or client IPs.
    for raw in (EMAIL, ENCODED_EMAIL, "jane.doe", VERIFIER, STATE, REQUEST_ID,
                CHALLENGE, NONCE, "127.0.0.1"):
        assert raw not in out, f"{raw!r} leaked into uvicorn output:\n{out}"
