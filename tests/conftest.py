"""Test-only environment defaults; production must supply its own secrets."""

import os


os.environ.setdefault("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")
