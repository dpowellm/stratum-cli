"""Learning loop detection rules.

Detects self-referential learning, unbounded memory, shared context,
and trajectory RL / fine-tuning patterns.
"""
from __future__ import annotations

import ast
import logging
import re

from stratum.models import (
    Confidence, Finding, RiskCategory, Severity,
)
from stratum.knowledge.learning_patterns import (
    MEMORY_STORES, CONTEXT_READ_METHODS, CONTEXT_WRITE_METHODS,
    DISTILLATION_SIGNALS, TRAJECTORY_RL_IMPORTS, SCOPING_PARAMS,
)
from stratum.research.owasp import get_owasp

logger = logging.getLogger(__name__)


def evaluate(
    py_files: list[tuple[str, str]],
) -> tuple[list[Finding], dict]:
    """Run learning risk rules across all Python files.

    Returns (findings, context) where context contains metadata
    for use by context_integrity and other dependent modules.
    """
    # Collect memory stores, read/write ops, collection names per file/scope
    all_stores: list[dict] = []        # detected memory store imports
    all_read_ops: list[dict] = []      # read operations
    all_write_ops: list[dict] = []     # write operations
    all_collections: list[dict] = []   # collection name references
    all_rl_signals: list[dict] = []    # trajectory RL / fine-tuning signals
    all_distillation: list[dict] = []  # distillation signals

    for file_path, content in py_files:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue

        # Collect imports
        file_imports: set[str] = set()
        file_full_imports: set[str] = set()  # full dotted names
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

        # Check for memory store imports
        for import_name, store_info in MEMORY_STORES.items():
            top_module = import_name.split(".")[0]
            if top_module in file_imports:
                all_stores.append({
                    "file": file_path,
                    "import": import_name,
                    "store_type": store_info["type"],
                    "learning_level": store_info["learning_level"],
                })

        # Check for trajectory RL imports
        for import_name, description in TRAJECTORY_RL_IMPORTS.items():
            if description is None:
                continue  # Only flag when specific usage is found
            top_module = import_name.split(".")[0]
            if any(imp.startswith(import_name) for imp in file_full_imports):
                all_rl_signals.append({
                    "file": file_path,
                    "import": import_name,
                    "description": description,
                })
            elif import_name in ("trl.PPOTrainer", "trl.DPOTrainer"):
                # Check if imported via from trl import PPOTrainer
                class_name = import_name.split(".")[-1]
                if f"trl.{class_name}" in file_full_imports or (
                    "trl" in file_imports and class_name in content
                ):
                    all_rl_signals.append({
                        "file": file_path,
                        "import": import_name,
                        "description": description,
                    })

        # Check for distillation signals
        for lib, methods in DISTILLATION_SIGNALS.items():
            if lib.split(".")[0] in file_imports:
                for method in methods:
                    if f".{method}(" in content:
                        all_distillation.append({
                            "file": file_path,
                            "library": lib,
                            "method": method,
                        })

        # Walk AST for read/write operations and collection names
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                method = node.func.attr

                # Detect read/write methods
                if method in CONTEXT_WRITE_METHODS:
                    scope = _get_scope_name(node, tree)
                    all_write_ops.append({
                        "file": file_path,
                        "method": method,
                        "line": node.lineno,
                        "scope": scope,
                        "has_metadata": _call_has_param(node, "metadata"),
                        "has_provenance": _call_has_provenance(node),
                    })

                if method in CONTEXT_READ_METHODS:
                    scope = _get_scope_name(node, tree)
                    all_read_ops.append({
                        "file": file_path,
                        "method": method,
                        "line": node.lineno,
                        "scope": scope,
                    })

            # Detect collection name strings (get_or_create_collection, create_collection, etc)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("get_or_create_collection", "create_collection",
                                       "get_collection", "Collection"):
                    if node.args and isinstance(node.args[0], ast.Constant):
                        coll_name = str(node.args[0].value)
                        scope = _get_scope_name(node, tree)
                        has_scoping = _collection_has_scoping(node, content)
                        all_collections.append({
                            "file": file_path,
                            "collection": coll_name,
                            "scope": scope,
                            "line": node.lineno,
                            "has_scoping": has_scoping,
                        })

    # Classify learning type (highest wins)
    learning_type = None
    if all_rl_signals:
        learning_type = "trajectory_rl"
    elif all_distillation:
        learning_type = "experience_distillation"
    elif all_stores and all_read_ops and all_write_ops:
        learning_type = "context_level"

    # Build context for dependent modules
    context = {
        "stores": all_stores,
        "read_ops": all_read_ops,
        "write_ops": all_write_ops,
        "collections": all_collections,
        "rl_signals": all_rl_signals,
        "distillation": all_distillation,
        "learning_type": learning_type,
        "has_learning_loop": bool(all_stores and all_read_ops and all_write_ops),
    }

    # Generate findings
    findings: list[Finding] = []

    # LEARNING-001: Learning loop detected
    if all_stores and all_read_ops and all_write_ops:
        # Find files that have BOTH read and write on memory stores
        files_with_reads = {op["file"] for op in all_read_ops}
        files_with_writes = {op["file"] for op in all_write_ops}
        store_files = {s["file"] for s in all_stores}

        loop_files = files_with_reads & files_with_writes & store_files

        if loop_files:
            # Determine severity based on learning type
            if learning_type == "trajectory_rl":
                severity = Severity.CRITICAL
                reversibility = "none"
            elif learning_type == "experience_distillation":
                severity = Severity.HIGH
                reversibility = "low"
            else:
                severity = Severity.MEDIUM
                reversibility = "high"

            # Get store name from collections or import
            store_name = "memory store"
            if all_collections:
                store_name = all_collections[0]["collection"]
            elif all_stores:
                store_name = all_stores[0]["import"]

            owasp_id, owasp_name = get_owasp("LEARNING-001")
            # Group by scope — find scopes with both read+write
            read_scopes = {(op["file"], op["scope"]) for op in all_read_ops}
            write_scopes = {(op["file"], op["scope"]) for op in all_write_ops}
            loop_scopes = read_scopes & write_scopes

            if loop_scopes:
                for file_path, scope in loop_scopes:
                    evidence = [f"{file_path}:{scope}"]
                    findings.append(Finding(
                        id="LEARNING-001",
                        severity=severity,
                        confidence=Confidence.CONFIRMED,
                        category=RiskCategory.OPERATIONAL,
                        title="Self-referential learning loop detected",
                        path=f"{scope} reads from and writes to '{store_name}'",
                        description=(
                            f"Agent reads from and writes to '{store_name}'. "
                            f"Over time, the agent's behavior will drift from what you deployed. "
                            f"Learning type: {learning_type}. Reversibility: {reversibility}."
                        ),
                        evidence=evidence,
                        remediation=_learning_remediation(learning_type),
                        owasp_id=owasp_id,
                        owasp_name=owasp_name,
                        finding_class="learning",
                    ))
            else:
                # File-level loop (read and write in same file but different scopes)
                for f in loop_files:
                    evidence = [f]
                    findings.append(Finding(
                        id="LEARNING-001",
                        severity=severity,
                        confidence=Confidence.PROBABLE,
                        category=RiskCategory.OPERATIONAL,
                        title="Self-referential learning loop detected",
                        path=f"File {f} reads from and writes to '{store_name}'",
                        description=(
                            f"Agent reads from and writes to '{store_name}'. "
                            f"Over time, the agent's behavior will drift from what you deployed. "
                            f"Learning type: {learning_type}. Reversibility: {reversibility}."
                        ),
                        evidence=evidence,
                        remediation=_learning_remediation(learning_type),
                        owasp_id=owasp_id,
                        owasp_name=owasp_name,
                        finding_class="learning",
                    ))

    # LEARNING-002: Unbounded memory accumulation
    if all_collections:
        unscoped = [c for c in all_collections if not c["has_scoping"]]
        if unscoped:
            coll = unscoped[0]
            owasp_id, owasp_name = get_owasp("LEARNING-002")
            findings.append(Finding(
                id="LEARNING-002",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category=RiskCategory.BUSINESS,
                title="Unbounded agent memory with no expiry or limits",
                path=f"Collection '{coll['collection']}' has no TTL, size limit, or namespace scoping",
                description=(
                    f"Memory store '{coll['collection']}' has no TTL, no size limit, and no access scoping. "
                    f"The agent will accumulate context indefinitely. This is both a drift risk "
                    f"(old context shapes new behavior unpredictably) and an attack surface "
                    f"(anyone who can write to the store can shape the agent's future behavior)."
                ),
                evidence=[f"{coll['file']}:{coll['line']}"],
                remediation=(
                    "Add TTL, size limit, and namespace scoping to the collection. "
                    "Implement periodic cleanup."
                ),
                owasp_id=owasp_id,
                owasp_name=owasp_name,
                finding_class="learning",
            ))

    # LEARNING-003: Shared context multi-agent
    # Check 1: Same collection name in different scopes
    # Check 2: Module-level collection used by multiple function scopes (via read/write ops)
    shared_detected = False
    if all_collections:
        coll_by_name: dict[str, list[dict]] = {}
        for c in all_collections:
            coll_by_name.setdefault(c["collection"], []).append(c)

        for coll_name, entries in coll_by_name.items():
            unique_scopes = {(e["file"], e["scope"]) for e in entries}
            if len(unique_scopes) >= 2:
                scopes_list = [f"{f}:{s}" for f, s in unique_scopes]
                scope_names = [s for _, s in unique_scopes]
                owasp_id, owasp_name = get_owasp("LEARNING-003")
                findings.append(Finding(
                    id="LEARNING-003",
                    severity=Severity.HIGH,
                    confidence=Confidence.PROBABLE,
                    category=RiskCategory.COMPOUNDING,
                    title="Multiple agents share the same memory store",
                    path=f"{' and '.join(scope_names)} reference collection '{coll_name}'",
                    description=(
                        f"Agents in {' and '.join(scope_names)} reference collection '{coll_name}'. "
                        f"If one agent writes poisoned or incorrect context, all agents that read "
                        f"from this store inherit the corruption simultaneously."
                    ),
                    evidence=scopes_list,
                    remediation=(
                        f"Use agent-specific namespaces: collection_name=f'memory_{{agent_id}}'. "
                        f"If shared context is intentional, add write validation and provenance tracking."
                    ),
                    owasp_id=owasp_id,
                    owasp_name=owasp_name,
                    finding_class="learning",
                ))
                shared_detected = True

        # Check 2: Module-level collection used by multiple function scopes
        if not shared_detected:
            for coll_name, entries in coll_by_name.items():
                # If collection is at module scope, check which function scopes use it
                module_entries = [e for e in entries if e["scope"] == "<module>"]
                if module_entries:
                    # Find function scopes that have read/write ops in same file
                    file_path = module_entries[0]["file"]
                    file_rw_scopes: set[str] = set()
                    for op in all_read_ops + all_write_ops:
                        if op["file"] == file_path and op["scope"] != "<module>":
                            file_rw_scopes.add(op["scope"])
                    if len(file_rw_scopes) >= 2:
                        scope_names = sorted(file_rw_scopes)
                        owasp_id, owasp_name = get_owasp("LEARNING-003")
                        findings.append(Finding(
                            id="LEARNING-003",
                            severity=Severity.HIGH,
                            confidence=Confidence.PROBABLE,
                            category=RiskCategory.COMPOUNDING,
                            title="Multiple agents share the same memory store",
                            path=f"{' and '.join(scope_names)} reference collection '{coll_name}'",
                            description=(
                                f"Agents {' and '.join(scope_names)} reference collection '{coll_name}'. "
                                f"If one agent writes poisoned or incorrect context, all agents that read "
                                f"from this store inherit the corruption simultaneously."
                            ),
                            evidence=[f"{file_path}:{s}" for s in scope_names],
                            remediation=(
                                f"Use agent-specific namespaces: collection_name=f'memory_{{agent_id}}'. "
                                f"If shared context is intentional, add write validation and provenance tracking."
                            ),
                            owasp_id=owasp_id,
                            owasp_name=owasp_name,
                            finding_class="learning",
                        ))
                        shared_detected = True

    if shared_detected:
        context["has_shared_context"] = True

    # LEARNING-004: Trajectory RL from production
    if all_rl_signals:
        for signal in all_rl_signals[:1]:  # One finding
            owasp_id, owasp_name = get_owasp("LEARNING-004")
            findings.append(Finding(
                id="LEARNING-004",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category=RiskCategory.SECURITY,
                title="Model fine-tuning from production data detected",
                path=f"{signal['file']} -> {signal['import']}",
                description=(
                    f"Fine-tuning or RL pipeline detected ({signal['description']}). "
                    f"Model weight updates from production data are irreversible without full retraining. "
                    f"Learned behaviors cannot be selectively removed."
                ),
                evidence=[signal["file"]],
                remediation=(
                    "Document the fine-tuning pipeline: data source, filtering criteria, "
                    "evaluation protocol, model versioning, rollback procedure. "
                    "Version every fine-tuned model checkpoint."
                ),
                owasp_id=owasp_id,
                owasp_name=owasp_name,
                finding_class="learning",
            ))

    return findings, context


def _learning_remediation(learning_type: str | None) -> str:
    """Return remediation text based on learning type."""
    if learning_type == "context_level":
        return (
            "Add provenance metadata to writes (timestamp, source, agent_id). "
            "Add TTL or max-size to prevent unbounded accumulation. "
            "Snapshot the store before each deployment."
        )
    elif learning_type == "experience_distillation":
        return (
            "Ensure trace-to-distillation pipeline has audit trail. "
            "Version distilled artifacts. Tag with source trace IDs."
        )
    elif learning_type == "trajectory_rl":
        return (
            "Fine-tuning from production data requires explicit governance. "
            "Document: what data, what filtering, what evaluation, what rollback. "
            "Version every fine-tuned model checkpoint."
        )
    return "Add provenance metadata and bounded retention to memory writes."


def _get_scope_name(node: ast.AST, tree: ast.Module) -> str:
    """Get the enclosing function/class name for a node."""
    # Walk the tree to find enclosing function
    for top_node in ast.walk(tree):
        if isinstance(top_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(top_node):
                if child is node:
                    return top_node.name
        elif isinstance(top_node, ast.ClassDef):
            for child in ast.walk(top_node):
                if child is node:
                    return top_node.name
    return "<module>"


def _call_has_param(node: ast.Call, param_name: str) -> bool:
    """Check if a call has a specific keyword parameter."""
    return any(kw.arg == param_name for kw in node.keywords)


def _call_has_provenance(node: ast.Call) -> bool:
    """Check if a write call includes provenance parameters."""
    from stratum.knowledge.learning_patterns import PROVENANCE_PARAMS
    return any(kw.arg in PROVENANCE_PARAMS for kw in node.keywords)


def _collection_has_scoping(node: ast.Call, content: str) -> bool:
    """Check if a collection creation has TTL, size, or namespace scoping."""
    # Check keyword arguments
    for kw in node.keywords:
        if kw.arg in SCOPING_PARAMS:
            return True
        if kw.arg == "metadata" and isinstance(kw.value, ast.Dict):
            for key in kw.value.keys:
                if isinstance(key, ast.Constant) and str(key.value) in SCOPING_PARAMS:
                    return True
    return False
