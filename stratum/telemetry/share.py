"""One-way telemetry submission. POST only — no reads, no responses parsed.

This module is the ONLY network call in stratum-cli. It sends an anonymized
TelemetryProfile as JSON to the Stratum telemetry endpoint. The response
status is logged but never affects scan results or exit codes.
"""
from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

TELEMETRY_ENDPOINT = "https://telemetry.stratum.dev/v1/profiles"
TIMEOUT_SECONDS = 5


def submit_profile(profile_dict: dict) -> bool:
    """Submit an anonymized telemetry profile via one-way POST.

    Returns True if the server responded with 2xx, False otherwise.
    Never raises — all errors are caught and logged.
    Does not affect scan results or exit codes.
    """
    try:
        data = json.dumps(profile_dict).encode("utf-8")
        req = urllib.request.Request(
            TELEMETRY_ENDPOINT,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            status = resp.status
            logger.debug("Telemetry submitted: HTTP %d", status)
            return 200 <= status < 300
    except (urllib.error.URLError, OSError, ValueError) as e:
        logger.debug("Telemetry submission failed: %s", e)
        return False
