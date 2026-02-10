"""Eval integrity rules.

Detects evaluation conflict of interest and missing eval frameworks.
"""
from __future__ import annotations

import ast
import logging

from stratum.models import (
    Confidence, Finding, RiskCategory, Severity,
)
from stratum.knowledge.learning_patterns import (
    EVAL_FRAMEWORKS, EVAL_CONFLICTS, MODEL_PROVIDERS,
)
from stratum.research.owasp import get_owasp

logger = logging.getLogger(__name__)


def evaluate(
    py_files: list[tuple[str, str]],
    telemetry_context: dict,
) -> tuple[list[Finding], dict]:
    """Run eval integrity rules.

    Returns (findings, context).
    """
    detected_evals: list[dict] = []
    detected_models = telemetry_context.get("model_providers", [])

    for file_path, content in py_files:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue

        file_imports: set[str] = set()
        file_full_imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    file_imports.add(alias.name.split(".")[0])
                    file_full_imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                file_imports.add(node.module.split(".")[0])
                file_full_imports.add(node.module)
                for alias in node.names:
                    file_full_imports.add(f"{node.module}.{alias.name}")

        for eval_key, info in EVAL_FRAMEWORKS.items():
            top = eval_key.split(".")[0]
            if top in file_imports:
                # For openai.evals, check full import
                if eval_key == "openai.evals":
                    if any(imp.startswith("openai.evals") for imp in file_full_imports) or \
                       "openai.evals" in content:
                        detected_evals.append({
                            "file": file_path,
                            "provider": info["provider"],
                            "parent_company": info["parent_company"],
                        })
                else:
                    detected_evals.append({
                        "file": file_path,
                        "provider": info["provider"],
                        "parent_company": info["parent_company"],
                    })

    # Deduplicate
    unique_evals = {}
    for e in detected_evals:
        if e["provider"] not in unique_evals:
            unique_evals[e["provider"]] = e

    unique_models = {}
    for m in detected_models:
        if m["provider"] not in unique_models:
            unique_models[m["provider"]] = m

    context = {
        "eval_providers": list(unique_evals.keys()),
        "has_eval_framework": bool(unique_evals),
        "has_eval_conflict": False,
    }

    findings: list[Finding] = []

    # EVAL-001: Model and eval share same ecosystem
    for e in unique_evals.values():
        for m in unique_models.values():
            eval_parent = e["parent_company"]
            model_parent = m["parent"]
            if (model_parent, eval_parent) in EVAL_CONFLICTS:
                owasp_id, owasp_name = get_owasp("EVAL-001")
                findings.append(Finding(
                    id="EVAL-001",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    category=RiskCategory.BUSINESS,
                    title="Model provider and evaluation share the same ecosystem",
                    path=f"{m['provider']} model + {e['provider']} evals",
                    description=(
                        f"Agent uses {m['provider']} for inference and {e['provider']} for "
                        f"evaluation. When the model provider also operates the evaluation "
                        f"layer, metrics may implicitly favor the provider's own models."
                    ),
                    evidence=[e.get("file", ""), m.get("file", "")],
                    remediation=(
                        "Consider adding an independent evaluation framework: "
                        "RAGAS (open source), DeepEval (open source), "
                        "or Promptfoo (open source, multi-provider)."
                    ),
                    owasp_id=owasp_id,
                    owasp_name=owasp_name,
                    finding_class="governance",
                ))
                context["has_eval_conflict"] = True
                break
        if context["has_eval_conflict"]:
            break

    # EVAL-002: No eval framework
    if not unique_evals:
        owasp_id, owasp_name = get_owasp("EVAL-002")
        findings.append(Finding(
            id="EVAL-002",
            severity=Severity.MEDIUM,
            confidence=Confidence.PROBABLE,
            category=RiskCategory.OPERATIONAL,
            title="No evaluation framework detected",
            path="No evaluation or testing framework found for agent outputs",
            description=(
                "No evaluation or testing framework found for agent outputs. "
                "Agent output quality is unmonitored -- you won't know when "
                "it degrades until users complain."
            ),
            evidence=["(no eval framework imports found)"],
            remediation=(
                "Add basic evals. Start simple: "
                "Promptfoo (YAML-based), DeepEval (pytest-like), "
                "or RAGAS (specialized for RAG pipelines)."
            ),
            owasp_id=owasp_id,
            owasp_name=owasp_name,
            finding_class="governance",
        ))

    return findings, context
