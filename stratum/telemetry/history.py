"""Local JSONL history + diff computation."""
from __future__ import annotations

import json
import logging
import os

from stratum.models import ScanDiff, ScanResult

logger = logging.getLogger(__name__)


def load_last(stratum_dir: str) -> dict | None:
    """Load the last scan entry from history.jsonl."""
    history_path = os.path.join(stratum_dir, "history.jsonl")
    try:
        if not os.path.exists(history_path):
            return None
        with open(history_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if not lines:
            return None
        last_line = lines[-1].strip()
        if not last_line:
            return None
        return json.loads(last_line)
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("Failed to load history: %s", e)
        return None


def save_history(result: ScanResult, stratum_dir: str) -> None:
    """Append a scan entry to history.jsonl."""
    try:
        os.makedirs(stratum_dir, exist_ok=True)
    except OSError:
        return

    history_path = os.path.join(stratum_dir, "history.jsonl")

    all_findings = result.top_paths + result.signals
    finding_ids = sorted(set(f.id for f in all_findings))

    entry = {
        "scan_id": result.scan_id,
        "ts": result.timestamp,
        "score": result.risk_score,
        "findings": finding_ids,
        "caps": result.total_capabilities,
        "guards": result.guardrail_count,
    }

    try:
        with open(history_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        # Prune to last 100
        _prune_history(history_path, max_entries=100)
    except OSError as e:
        logger.debug("Failed to save history: %s", e)


def compute_diff(result: ScanResult, prev: dict) -> ScanDiff:
    """Compute the diff between current scan and previous entry."""
    prev_score = prev.get("score", 0)
    prev_finding_ids = set(prev.get("findings", []))

    current_finding_ids = set(
        f.id for f in result.top_paths + result.signals
    )

    new_ids = sorted(current_finding_ids - prev_finding_ids)
    resolved_ids = sorted(prev_finding_ids - current_finding_ids)

    return ScanDiff(
        previous_risk_score=prev_score,
        risk_score_delta=result.risk_score - prev_score,
        new_finding_ids=new_ids,
        resolved_finding_ids=resolved_ids,
    )


def _prune_history(history_path: str, max_entries: int = 100) -> None:
    """Prune history file to keep only the last N entries."""
    try:
        with open(history_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if len(lines) > max_entries:
            with open(history_path, "w", encoding="utf-8") as f:
                f.writelines(lines[-max_entries:])
    except OSError:
        pass
