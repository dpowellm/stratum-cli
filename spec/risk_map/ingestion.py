"""Ingest telemetry profiles into an append-only JSONL store."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict

from stratum.models import TelemetryProfile

logger = logging.getLogger(__name__)


class ProfileStore:
    """Append-only JSONL store for telemetry profiles."""

    def __init__(self, store_path: str) -> None:
        self.store_path = store_path
        os.makedirs(os.path.dirname(store_path) or ".", exist_ok=True)

    def ingest_profile(self, profile: TelemetryProfile) -> bool:
        """Validate, deduplicate, and append a profile."""
        if not profile.scan_id:
            logger.warning("Rejecting profile with no scan_id")
            return False

        # Check for duplicate
        if self._exists(profile.scan_id):
            logger.debug("Duplicate profile %s, skipping", profile.scan_id)
            return False

        try:
            with open(self.store_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(profile)) + "\n")
            return True
        except OSError as e:
            logger.error("Failed to write profile: %s", e)
            return False

    def load_all(self) -> list[dict]:
        """Load all profiles from the store."""
        profiles: list[dict] = []
        try:
            with open(self.store_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            profiles.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except OSError:
            pass
        return profiles

    def _exists(self, scan_id: str) -> bool:
        """Check if a scan_id already exists in the store."""
        try:
            with open(self.store_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        if entry.get("scan_id") == scan_id:
                            return True
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass
        return False
