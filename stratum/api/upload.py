"""Profile upload client for Stratum API.

Uploads ScanProfiles to the Stratum dashboard for team/org visibility.
Requires a Stratum API token (from stratum.dev/settings).

Usage from CLI:
    stratum scan . --upload --token st_...

Usage from GitHub Action:
    The action handles upload automatically when stratum-token is set.
"""
from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

UPLOAD_ENDPOINT = "https://api.stratum.dev/v1/profiles"
TIMEOUT_SECONDS = 10


def upload_profile(
    profile_dict: dict,
    token: str,
    endpoint: str = UPLOAD_ENDPOINT,
) -> tuple[bool, str]:
    """Upload a ScanProfile to the Stratum API.

    Args:
        profile_dict: ScanProfile as a dict (from dataclasses.asdict).
        token: Stratum API bearer token.
        endpoint: API endpoint URL.

    Returns:
        (success: bool, message: str)
    """
    # Reject empty profiles — no point storing them
    if profile_dict.get("framework_parse_quality") == "empty":
        return False, "Skipped: empty profile (no frameworks detected)"

    try:
        data = json.dumps(profile_dict).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "stratum-cli",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            status = resp.status
            body = resp.read().decode("utf-8")
            if 200 <= status < 300:
                logger.debug("Profile uploaded: HTTP %d", status)
                return True, f"Uploaded (HTTP {status})"
            else:
                return False, f"Server returned HTTP {status}: {body[:200]}"

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:200] if hasattr(e, "read") else ""
        msg = f"HTTP {e.code}: {body}"
        logger.warning("Profile upload failed: %s", msg)
        return False, msg
    except (urllib.error.URLError, OSError, ValueError) as e:
        msg = str(e)
        logger.warning("Profile upload failed: %s", msg)
        return False, msg


def check_org_trigger(
    org_id: str,
    token: str,
    endpoint: str = "https://api.stratum.dev/v1/orgs",
    threshold: int = 3,
) -> tuple[bool, int]:
    """Check if an org has reached the fleet report trigger threshold.

    Returns (triggered: bool, repo_count: int).
    This is used by the upload flow to detect when to generate fleet reports.
    """
    try:
        url = f"{endpoint}/{org_id}/profile-count"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": "stratum-cli",
            },
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            count = data.get("count", 0)
            return count >= threshold, count
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        logger.debug("Org trigger check failed: %s", e)
        return False, 0
