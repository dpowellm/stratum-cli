"""Telemetry destination detection rules.

Detects where agent execution traces go and flags data concentration risks.
"""
from __future__ import annotations

import ast
import logging

from stratum.models import (
    Confidence, Finding, RiskCategory, Severity,
)
from stratum.knowledge.learning_patterns import (
    TELEMETRY_PROVIDERS, MODEL_PROVIDERS, PROVIDER_CONFLICTS,
)
from stratum.research.owasp import get_owasp

logger = logging.getLogger(__name__)


def evaluate(
    py_files: list[tuple[str, str]],
    env_vars: list[str],
) -> tuple[list[Finding], dict]:
    """Run telemetry destination rules.

    Returns (findings, context) where context contains detected providers.
    """
    # Detect telemetry providers from imports
    detected_telemetry: list[dict] = []
    detected_models: list[dict] = []

    for file_path, content in py_files:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue

        file_imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    file_imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                file_imports.add(node.module.split(".")[0])

        # Check telemetry provider imports
        for provider_key, info in TELEMETRY_PROVIDERS.items():
            top = provider_key.split(".")[0]
            if top in file_imports:
                detected_telemetry.append({
                    "file": file_path,
                    "provider": info["provider"],
                    "parent_company": info["parent_company"],
                })

        # Check model provider imports
        for provider_key, display_name in MODEL_PROVIDERS.items():
            top = provider_key.split(".")[0]
            if top in file_imports:
                detected_models.append({
                    "file": file_path,
                    "provider": display_name,
                    "key": provider_key,
                    "parent": top,
                })

    # Also detect telemetry from env vars
    for provider_key, info in TELEMETRY_PROVIDERS.items():
        for env_key in info["env_keys"]:
            if env_key in env_vars:
                if not any(d["provider"] == info["provider"] for d in detected_telemetry):
                    detected_telemetry.append({
                        "file": ".env",
                        "provider": info["provider"],
                        "parent_company": info["parent_company"],
                    })

    # Also check env vars referenced in Python code
    for file_path, content in py_files:
        for provider_key, info in TELEMETRY_PROVIDERS.items():
            for env_key in info["env_keys"]:
                if f'"{env_key}"' in content or f"'{env_key}'" in content:
                    if not any(
                        d["provider"] == info["provider"] and d["file"] == file_path
                        for d in detected_telemetry
                    ):
                        detected_telemetry.append({
                            "file": file_path,
                            "provider": info["provider"],
                            "parent_company": info["parent_company"],
                        })

    context = {
        "telemetry_providers": detected_telemetry,
        "model_providers": detected_models,
        "telemetry_destinations": list({d["provider"] for d in detected_telemetry}),
    }

    findings: list[Finding] = []

    # Deduplicate telemetry providers
    unique_telemetry = {}
    for t in detected_telemetry:
        if t["provider"] not in unique_telemetry:
            unique_telemetry[t["provider"]] = t

    unique_models = {}
    for m in detected_models:
        if m["provider"] not in unique_models:
            unique_models[m["provider"]] = m

    # TELEMETRY-002: Trace data to model provider (check first, higher severity)
    trace_to_provider = False
    for t in unique_telemetry.values():
        for m in unique_models.values():
            conflict_key = (t["parent_company"], m["parent"])
            if conflict_key in PROVIDER_CONFLICTS:
                conflict_desc = PROVIDER_CONFLICTS[conflict_key]
                owasp_id, owasp_name = get_owasp("TELEMETRY-002")
                findings.append(Finding(
                    id="TELEMETRY-002",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    category=RiskCategory.COMPLIANCE,
                    title="Trace data flows back to model/platform provider",
                    path=f"{t['provider']} traces + {m['provider']} model",
                    description=(
                        f"{conflict_desc}. This creates informational asymmetry: "
                        f"the provider observes your agent's business logic, tool usage, "
                        f"failure modes, and customer interaction patterns."
                    ),
                    evidence=[t.get("file", ""), m.get("file", "")],
                    remediation=(
                        "Use a provider-independent observability stack: "
                        "Langfuse (open source, self-hostable), "
                        "OpenTelemetry + your own collector, "
                        "or MLflow (self-hostable)."
                    ),
                    owasp_id=owasp_id,
                    owasp_name=owasp_name,
                    finding_class="governance",
                ))
                trace_to_provider = True
                break
        if trace_to_provider:
            break

    context["has_trace_to_model_provider"] = trace_to_provider

    # TELEMETRY-001: External telemetry destination
    if unique_telemetry:
        for provider_name, t in unique_telemetry.items():
            owasp_id, owasp_name = get_owasp("TELEMETRY-001")
            findings.append(Finding(
                id="TELEMETRY-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category=RiskCategory.COMPLIANCE,
                title="Agent traces sent to external provider",
                path=f"Execution traces -> {provider_name}",
                description=(
                    f"Execution traces are sent to {provider_name}. Trace data includes tool "
                    f"calls, model inputs/outputs, and error details. This data may contain "
                    f"business logic, customer data, and agent behavior patterns."
                ),
                evidence=[t.get("file", "")],
                remediation=(
                    f"Review {provider_name}'s data retention and usage policies. "
                    f"Consider self-hosted alternatives: Langfuse (self-host), MLflow (self-host), "
                    f"OpenTelemetry with your own collector."
                ),
                owasp_id=owasp_id,
                owasp_name=owasp_name,
                finding_class="governance",
            ))

    # TELEMETRY-003: No telemetry at all
    if not unique_telemetry:
        owasp_id, owasp_name = get_owasp("TELEMETRY-003")
        findings.append(Finding(
            id="TELEMETRY-003",
            severity=Severity.LOW,
            confidence=Confidence.PROBABLE,
            category=RiskCategory.OPERATIONAL,
            title="No observability or tracing detected",
            path="No telemetry SDK or tracing configuration found",
            description=(
                "No telemetry SDK or tracing configuration found. Agent behavior "
                "cannot be audited, monitored for drift, or debugged in production."
            ),
            evidence=["(no telemetry imports or env vars found)"],
            remediation=(
                "Add observability. Options: "
                "Langfuse (open source): pip install langfuse, "
                "LangSmith: set LANGCHAIN_TRACING_V2=true, "
                "OpenTelemetry: vendor-neutral, self-hostable."
            ),
            owasp_id=owasp_id,
            owasp_name=owasp_name,
            finding_class="governance",
        ))

    return findings, context
