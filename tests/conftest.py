"""Test-only environment defaults; production must supply its own secrets."""

from __future__ import annotations

import os
import pytest

os.environ.setdefault("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")


@pytest.fixture(autouse=True)
def _isolate_test_env():
    """Ensure sensitive environment variables don't leak across test runs."""
    yield
    os.environ.pop("BRDS_API_KEY", None)
    os.environ.pop("BRDS_LIVE_CONTAINMENT", None)
