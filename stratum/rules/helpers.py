"""Shared helpers for evidence scoping across rule modules."""
from __future__ import annotations


def scope_evidence_to_project(
    evidence: list[str],
    reference_file: str,
    max_items: int = 3,
) -> list[str]:
    """Filter evidence to files sharing a project root with reference_file.

    The "project root" is the first two directory components of a path,
    e.g. ``crews/match_profile_to_positions`` or ``flows/email_auto_responder_flow``.

    Falls back to the original evidence (capped at *max_items*) if nothing
    matches — this ensures at least some evidence is always present.
    """
    if not reference_file:
        return evidence[:max_items]

    ref_root = _get_project_root(reference_file)
    scoped = [
        ev for ev in evidence
        if _shares_root(ref_root, ev.split(":")[0])
    ]

    result = scoped if scoped else evidence
    return result[:max_items]


def limit_evidence(evidence: list[str], max_items: int = 4) -> list[str]:
    """Keep the most specific evidence items.

    Priority: file paths with line numbers > file paths > metadata.
    """
    if len(evidence) <= max_items:
        return evidence
    with_lines = [e for e in evidence if ":" in e and not e.endswith(":0")]
    # File paths (contain / or \) without line numbers
    file_paths = [
        e for e in evidence
        if e not in with_lines and ("/" in e or "\\" in e)
        and not e.startswith("Crew:") and not e.startswith("Shared")
        and not e.startswith("Downstream:")
    ]
    metadata = [e for e in evidence if e not in with_lines and e not in file_paths]
    return (with_lines + file_paths + metadata)[:max_items]


def _get_project_root(path: str) -> str:
    """Extract the first 2 directory components as project root.

    ``crews/match_profile_to_positions/src/foo.py`` → ``crews/match_profile_to_positions``
    """
    parts = path.replace("\\", "/").split("/")
    return "/".join(parts[:2]).lower() if len(parts) >= 2 else parts[0].lower()


def _shares_root(root: str, path: str) -> bool:
    return _get_project_root(path) == root
