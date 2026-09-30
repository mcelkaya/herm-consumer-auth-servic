"""The Dockerfile HEALTHCHECK must hit a real, dependency-free liveness route
and must fail when that route does not answer 2xx.

Reproduces: the HEALTHCHECK requested ``/herm-auth/health`` (no such route,
404) via ``requests.get`` without ``raise_for_status()``, so the probe
"passed" on a 404 and never detected an unhealthy app.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

_DOCKERFILE = Path(__file__).resolve().parents[2] / "Dockerfile"


def _healthcheck_cmd() -> str:
    match = re.search(r"HEALTHCHECK[^\n]*\\\n\s*CMD(?P<cmd>[^\n]*)", _DOCKERFILE.read_text())
    assert match, "Dockerfile has no HEALTHCHECK CMD"
    return match.group("cmd")


def _healthcheck_path() -> str:
    match = re.search(r"http://localhost:8000(?P<path>/[^'\"\s]*)", _healthcheck_cmd())
    assert match, "HEALTHCHECK does not probe localhost:8000"
    return match.group("path")


@pytest.mark.unit
def test_healthcheck_hits_liveness_route():
    # Without entering the context manager the lifespan (Redis) never runs:
    # liveness must answer without any downstream dependency.
    response = TestClient(app).get(_healthcheck_path())

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


@pytest.mark.unit
def test_healthcheck_fails_on_http_error():
    # requests.get() does not raise on 4xx/5xx; the probe must.
    assert "raise_for_status()" in _healthcheck_cmd()
