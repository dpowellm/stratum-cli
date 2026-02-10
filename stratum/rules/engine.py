"""Severity gating + top-5 selection engine.

Enforces the hard acceptance criterion: zero CRITICAL/HIGH from HEURISTIC evidence.
"""
from __future__ import annotations

import logging

from stratum.models import (
    Capability, Confidence, Finding, GuardrailSignal,
    MCPServer, Severity,
)
from stratum.rules import paths
from stratum.rules import learning_risk
from stratum.rules import context_integrity
from stratum.rules import telemetry_dest
from stratum.rules import eval_integrity
from stratum.rules import agent_identity
from stratum.rules import portability_risk

logger = logging.getLogger(__name__)


def _gate_severity(finding: Finding) -> Finding:
    """Post-processing gate that ENFORCES the acceptance criterion.

    HEURISTIC -> max MEDIUM. PROBABLE -> max HIGH. Only CONFIRMED -> CRITICAL.
    Called on every finding after all rules have run. No exceptions.
    """
    original = finding.severity

    if finding.confidence == Confidence.HEURISTIC:
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            finding.severity = Severity.MEDIUM

    elif finding.confidence == Confidence.PROBABLE:
        if finding.severity == Severity.CRITICAL:
            finding.severity = Severity.HIGH

    logger.info(
        "_gate_severity: %s severity=%s->%s confidence=%s",
        finding.id, original.value, finding.severity.value, finding.confidence.value,
    )
    return finding


def _finding_key(f: Finding) -> tuple[str, tuple[str, ...]]:
    """Stable dedup/identity key. Used for BOTH dedup AND top/signal split."""
    return (f.id, tuple(sorted(f.evidence)))


class Engine:
    """Risk evaluation engine."""

    def evaluate(
        self,
        capabilities: list[Capability],
        mcp_servers: list[MCPServer],
        guardrails: list[GuardrailSignal],
        env_vars: list[str],
        env_findings: list[Finding],
        checkpoint_type: str,
        py_files: list[tuple[str, str]] | None = None,
    ) -> tuple[list[Finding], list[Finding], dict]:
        """Run all rules, gate severity, deduplicate, split into top_paths + signals.

        Returns (top_paths, signals, governance_context).
        """
        all_findings: list[Finding] = []

        # Path rules (all 10)
        all_findings.extend(
            paths.evaluate(capabilities, mcp_servers, guardrails, checkpoint_type)
        )

        # Env findings
        all_findings.extend(env_findings)

        # Learning & Governance rules (only when py_files provided)
        governance_context: dict = {}
        if py_files:
            # Learning risk
            learning_findings, learning_ctx = learning_risk.evaluate(py_files)
            all_findings.extend(learning_findings)

            # Context integrity (depends on learning context)
            context_findings = context_integrity.evaluate(py_files, learning_ctx)
            all_findings.extend(context_findings)

            # Telemetry destination
            telemetry_findings, telemetry_ctx = telemetry_dest.evaluate(py_files, env_vars)
            all_findings.extend(telemetry_findings)

            # Eval integrity
            eval_findings, eval_ctx = eval_integrity.evaluate(py_files, telemetry_ctx)
            all_findings.extend(eval_findings)

            # Agent identity
            identity_findings, identity_ctx = agent_identity.evaluate(py_files, telemetry_ctx)
            all_findings.extend(identity_findings)

            # Portability risk
            portability_findings = portability_risk.evaluate(py_files, guardrails, telemetry_ctx)
            all_findings.extend(portability_findings)

            governance_context = {
                "learning": learning_ctx,
                "telemetry": telemetry_ctx,
                "eval": eval_ctx,
                "identity": identity_ctx,
            }

        # ENFORCE acceptance criterion: gate every finding
        for i, f in enumerate(all_findings):
            all_findings[i] = _gate_severity(f)

        # Deduplicate by stable key
        seen: set[tuple[str, tuple[str, ...]]] = set()
        deduped: list[Finding] = []
        for f in all_findings:
            key = _finding_key(f)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        # Sort: severity desc -> confidence desc -> len(evidence) desc
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2, Severity.LOW: 3,
        }
        confidence_order = {
            Confidence.CONFIRMED: 0, Confidence.PROBABLE: 1,
            Confidence.HEURISTIC: 2,
        }
        deduped.sort(key=lambda f: (
            severity_order[f.severity],
            confidence_order[f.confidence],
            -len(f.evidence),
        ))

        # Top paths: first 5 that are NOT heuristic-only
        top = [f for f in deduped if f.confidence != Confidence.HEURISTIC][:5]
        top_keys = {_finding_key(f) for f in top}
        signals = [f for f in deduped if _finding_key(f) not in top_keys]

        return top, signals, governance_context
