"""Context integrity rules.

Detects missing integrity controls on agent context and memory.
These findings only fire when a learning pattern is detected.
"""
from __future__ import annotations

import ast
import logging

from stratum.models import (
    Confidence, Finding, RiskCategory, Severity,
)
from stratum.research.owasp import get_owasp

logger = logging.getLogger(__name__)


def evaluate(
    py_files: list[tuple[str, str]],
    learning_context: dict,
) -> list[Finding]:
    """Run context integrity rules. Only fires when learning patterns exist."""
    findings: list[Finding] = []

    if not learning_context.get("has_learning_loop"):
        return findings

    stores = learning_context.get("stores", [])
    write_ops = learning_context.get("write_ops", [])
    collections = learning_context.get("collections", [])

    if not stores:
        return findings

    store_name = "memory store"
    if collections:
        store_name = collections[0]["collection"]
    elif stores:
        store_name = stores[0]["import"]

    # CONTEXT-001: No provenance on writes
    writes_with_provenance = [w for w in write_ops if w.get("has_provenance")]
    if write_ops and not writes_with_provenance:
        owasp_id, owasp_name = get_owasp("CONTEXT-001")
        findings.append(Finding(
            id="CONTEXT-001",
            severity=Severity.MEDIUM,
            confidence=Confidence.PROBABLE,
            category=RiskCategory.COMPLIANCE,
            title="Memory writes have no provenance tracking",
            path=f"Writes to '{store_name}' include no attribution metadata",
            description=(
                f"Writes to '{store_name}' include no attribution metadata (source, timestamp, "
                f"agent_id). When the agent learns something wrong, you cannot determine "
                f"which input caused it or when it entered the store."
            ),
            evidence=[f"{w['file']}:{w['line']}" for w in write_ops[:3]],
            remediation=(
                "Add metadata to writes: "
                "collection.add(documents=[doc], metadatas=[{"
                "'source': 'tool_result', 'agent_id': AGENT_ID, "
                "'timestamp': datetime.utcnow().isoformat()}])"
            ),
            owasp_id=owasp_id,
            owasp_name=owasp_name,
            finding_class="learning",
        ))

    # CONTEXT-002: No rollback / versioning
    has_rollback = _detect_rollback(py_files)
    if not has_rollback:
        owasp_id, owasp_name = get_owasp("CONTEXT-002")
        store_type = stores[0]["import"] if stores else "memory"
        findings.append(Finding(
            id="CONTEXT-002",
            severity=Severity.MEDIUM,
            confidence=Confidence.PROBABLE,
            category=RiskCategory.OPERATIONAL,
            title="No versioning or rollback on agent memory",
            path=f"No snapshot, backup, or versioning pattern detected for '{store_name}'",
            description=(
                f"No snapshot, backup, or versioning pattern detected for {store_type} store. "
                f"If the agent accumulates bad context, you have no mechanism to revert "
                f"to a known-good state."
            ),
            evidence=["(no backup/snapshot pattern found)"],
            remediation=(
                "Snapshot before deployments. Use a vector store with built-in versioning "
                "or implement periodic backup of the persist directory."
            ),
            owasp_id=owasp_id,
            owasp_name=owasp_name,
            finding_class="learning",
        ))

    # CONTEXT-003: Unprotected shared context writes
    has_shared = learning_context.get("has_shared_context", False)
    if has_shared:
        # Check if writes have namespace or auth
        writes_with_scoping = [
            w for w in write_ops
            if w.get("has_provenance")  # provenance includes agent_id
        ]
        if not writes_with_scoping:
            coll_name = store_name
            owasp_id, owasp_name = get_owasp("CONTEXT-003")
            findings.append(Finding(
                id="CONTEXT-003",
                severity=Severity.HIGH,
                confidence=Confidence.PROBABLE,
                category=RiskCategory.SECURITY,
                title="Unscoped writes to shared agent memory",
                path=f"Any agent can write to collection '{coll_name}' with no permission check",
                description=(
                    f"Any agent can write to collection '{coll_name}' with no "
                    f"authentication, namespace scoping, or permission check. A compromised "
                    f"or misbehaving agent can poison the shared context for all consumers."
                ),
                evidence=[f"{w['file']}:{w['line']}" for w in write_ops[:3]],
                remediation=(
                    "Scope writes by agent: "
                    "collection.add(documents=[doc], ids=[f'{agent_id}_{doc_id}'], "
                    "metadatas=[{'author_agent': agent_id}])"
                ),
                owasp_id=owasp_id,
                owasp_name=owasp_name,
                finding_class="learning",
            ))

    return findings


def _detect_rollback(py_files: list[tuple[str, str]]) -> bool:
    """Check if any file contains rollback/snapshot patterns."""
    rollback_patterns = [
        ".snapshot(", ".backup(", "version=",
        "copytree(", "shutil.copy",
        "def backup", "def snapshot", "def rollback",
    ]
    for _, content in py_files:
        for pattern in rollback_patterns:
            if pattern in content:
                return True
    return False
