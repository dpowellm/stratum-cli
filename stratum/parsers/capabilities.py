"""AST-based capability detection for Python files.

The core of the scanner. Reads Python files and finds dangerous function-level
capabilities via AST. Framework-agnostic: if a function has subprocess.run(),
we find it regardless of whether it's LangGraph, CrewAI, or raw Python.
"""
from __future__ import annotations

import ast
import logging
from typing import Any

from stratum.models import Capability, Confidence, GuardrailSignal, TrustLevel
from stratum.knowledge.db import (
    OUTBOUND_IMPORTS, OUTBOUND_METHODS,
    DATA_ACCESS_IMPORTS, DATA_ACCESS_METHODS, DB_CURSOR_NAMES,
    CODE_EXEC_FUNCTIONS, CODE_EXEC_BUILTINS,
    DESTRUCTIVE_SQL_KEYWORDS, DESTRUCTIVE_METHODS,
    FINANCIAL_IMPORTS, HTTP_LIBRARIES,
)
from stratum.framework_tools import (
    KNOWN_TOOLS, AGENT_FRAMEWORK_IMPORTS, CODE_EXEC_CONSTRUCTORS,
)

logger = logging.getLogger(__name__)


def scan_python_file(file_path: str, content: str) -> tuple[list[Capability], list[GuardrailSignal]]:
    """Scan a Python file for dangerous capabilities and guardrail signals."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        logger.debug("Failed to parse %s", file_path)
        return [], []

    # Step 1b: Collect module-level imports
    file_imports: set[str] = set()
    file_alias_map: dict[str, str] = {}
    _collect_imports(tree.body, file_imports, file_alias_map)

    # Step 2: Find all function definitions
    capabilities: list[Capability] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            caps = _scan_function(node, file_path, file_imports, file_alias_map, content)
            capabilities.extend(caps)

    # Step 4: Detect guardrail signals
    guardrails = _detect_guardrails(tree, file_path, content)

    # Step 5: Framework tool detection (Layer 1 + Layer 3)
    framework_caps = detect_framework_tools(file_imports, file_alias_map, tree, file_path)
    capabilities.extend(framework_caps)

    # Step 6: Framework guardrail detection
    framework_guardrails = detect_framework_guardrails(file_imports, file_alias_map, tree, file_path)
    guardrails.extend(framework_guardrails)

    return capabilities, guardrails


def _collect_imports(
    body: list[ast.stmt],
    imports: set[str],
    alias_map: dict[str, str],
) -> None:
    """Collect imports and alias mappings from a list of AST statements."""
    for node in body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                imports.add(name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imports.add(module.split(".")[0])
            for alias in node.names:
                local_name = alias.asname or alias.name
                alias_map[local_name] = module


def _get_root_name(node: Any) -> str:
    """Recursively resolve chained attributes to the root Name.

    stripe.Refund.create() -> "stripe"
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _get_root_name(node.value)
    return ""


def _resolve_call_origin(
    call_node: ast.Call,
    known_imports: set[str],
    alias_map: dict[str, str],
    var_origin: dict[str, str],
) -> tuple[str, str]:
    """Resolve a call node to (object_name, method_name).

    Returns the object name and method for attribute calls,
    or (function_name, "") for simple Name calls.
    """
    func = call_node.func
    if isinstance(func, ast.Attribute):
        method = func.attr
        if isinstance(func.value, ast.Name):
            return func.value.id, method
        elif isinstance(func.value, ast.Attribute):
            root = _get_root_name(func.value)
            return root, method
        return "", method
    elif isinstance(func, ast.Name):
        return func.id, ""
    return "", ""


def _resolve_confidence(
    obj_name: str,
    method: str,
    known_imports: set[str],
    alias_map: dict[str, str],
    var_origin: dict[str, str],
) -> tuple[Confidence, str]:
    """Determine confidence and origin module for obj.method() calls.

    Checks three provenance sources in order:
    1. known_imports: obj is a directly imported module
    2. alias_map: obj was imported via 'from X import obj'
    3. var_origin: obj was assigned from a confirmed constructor

    Returns (confidence, origin_module).
    """
    if not obj_name:
        return Confidence.HEURISTIC, ""

    # Source 1: Direct import
    if obj_name in known_imports:
        return Confidence.CONFIRMED, obj_name

    # Source 2: Alias
    if obj_name in alias_map:
        top_module = alias_map[obj_name].split(".")[0]
        return Confidence.CONFIRMED, top_module

    # Source 3: Variable provenance
    if obj_name in var_origin:
        return Confidence.CONFIRMED, var_origin[obj_name]

    # Source 4: DB cursor convention
    if obj_name in DB_CURSOR_NAMES:
        db_lib = _first_db_import(known_imports)
        if db_lib:
            return Confidence.CONFIRMED, db_lib

    return Confidence.HEURISTIC, ""


def _first_db_import(known_imports: set[str]) -> str:
    """Find the first DB import in known_imports."""
    for lib in DATA_ACCESS_IMPORTS:
        top = lib.split(".")[0]
        if top in known_imports:
            return top
    return ""


def _build_var_origin(
    func_node: ast.AST,
    known_imports: set[str],
    alias_map: dict[str, str],
) -> dict[str, str]:
    """Build a map from variable names to their origin module.

    Processes assignments like:
    - server = smtplib.SMTP(...)  -> var_origin["server"] = "smtplib"
    - client = WebClient(...)     -> var_origin["client"] = "slack_sdk" (via alias_map)
    - conn = psycopg2.connect(...) -> var_origin["conn"] = "psycopg2"
    - cursor = conn.cursor()      -> var_origin["cursor"] = "psycopg2" (via chain)
    """
    var_origin: dict[str, str] = {}

    for node in ast.walk(func_node):
        if not isinstance(node, ast.Assign):
            continue
        if len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        var_name = target.id
        value = node.value

        origin = _resolve_value_origin(value, known_imports, alias_map, var_origin)
        if origin:
            var_origin[var_name] = origin

    return var_origin


def _resolve_value_origin(
    value: ast.expr,
    known_imports: set[str],
    alias_map: dict[str, str],
    var_origin: dict[str, str],
) -> str:
    """Resolve the origin module of an assignment value expression."""
    if isinstance(value, ast.Call):
        func = value.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                obj = func.value.id
                if obj in known_imports:
                    return obj
                if obj in alias_map:
                    return alias_map[obj].split(".")[0]
                if obj in var_origin:
                    return var_origin[obj]
            elif isinstance(func.value, ast.Attribute):
                root = _get_root_name(func.value)
                if root in known_imports:
                    return root
                if root in alias_map:
                    return alias_map[root].split(".")[0]
                if root in var_origin:
                    return var_origin[root]
        elif isinstance(func, ast.Name):
            name = func.id
            if name in alias_map:
                return alias_map[name].split(".")[0]
            if name in known_imports:
                return name
    return ""


def _has_error_handling(func_node: ast.AST, call_line: int) -> bool:
    """Check if the call at call_line is inside a try/except block.

    Walk the function body looking for ast.Try nodes.
    For each Try, check if call_line falls within the line range of the try body.
    """
    for node in ast.walk(func_node):
        if isinstance(node, ast.Try):
            if node.body:
                try_start = node.body[0].lineno
                try_end = max(
                    getattr(stmt, "end_lineno", stmt.lineno)
                    for stmt in node.body
                )
                if try_start <= call_line <= try_end:
                    return True
    return False


def _has_timeout(node: ast.Call) -> bool:
    """Check if an HTTP call has a timeout parameter."""
    return any(kw.arg == "timeout" for kw in node.keywords)


def _has_input_validation(func_node: ast.AST) -> bool:
    """Check if function has any input validation before dangerous calls.

    Looks for isinstance(), comparisons, assert, if/raise patterns,
    pydantic model_validate, TypeAdapter.
    """
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "isinstance":
                return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("model_validate", "TypeAdapter"):
                return True
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, ast.Compare):
            return True
        if isinstance(node, ast.If):
            for child in ast.walk(node):
                if isinstance(child, ast.Raise):
                    return True
    return False


def _is_outbound_import(lib: str) -> bool:
    """Check if a library is an outbound import."""
    return lib in OUTBOUND_IMPORTS or any(
        lib == imp.split(".")[0] for imp in OUTBOUND_IMPORTS
    )


def _is_data_access_import(lib: str) -> bool:
    """Check if a library is a data access import."""
    return lib in DATA_ACCESS_IMPORTS or any(
        lib == imp.split(".")[0] for imp in DATA_ACCESS_IMPORTS
    )


def _is_financial_import(lib: str) -> bool:
    """Check if a library is a financial import."""
    return lib in FINANCIAL_IMPORTS


def _check_destructive_sql(func_node: ast.AST, known_imports: set[str],
                           alias_map: dict[str, str],
                           var_origin: dict[str, str]) -> list[tuple[int, str, Confidence]]:
    """Check for destructive SQL patterns inside .execute() calls on DB cursors.

    Returns list of (line_number, evidence, confidence) tuples.
    """
    results: list[tuple[int, str, Confidence]] = []

    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "execute":
            continue

        obj_name = ""
        if isinstance(node.func.value, ast.Name):
            obj_name = node.func.value.id

        if not obj_name:
            continue

        # Check if the object traces to a DB import
        conf, origin = _resolve_confidence(obj_name, "execute", known_imports,
                                           alias_map, var_origin)
        if conf != Confidence.CONFIRMED or not _is_data_access_import(origin):
            continue

        # Check the first argument for destructive SQL keywords
        if not node.args:
            continue

        sql_str = _extract_string_value(node.args[0])
        if not sql_str:
            continue

        sql_upper = sql_str.upper()
        for keyword in DESTRUCTIVE_SQL_KEYWORDS:
            if keyword in sql_upper:
                results.append((
                    node.lineno,
                    f"{obj_name}.execute() contains {keyword}",
                    Confidence.CONFIRMED,
                ))
                break

    return results


def _extract_string_value(node: ast.expr) -> str:
    """Extract string content from AST node (handles f-strings, constants)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                parts.append(val.value)
        return "".join(parts)
    return ""


def _get_source_line(content: str, lineno: int) -> str:
    """Extract a single source line by line number. Returns empty string on failure."""
    lines = content.split("\n")
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""


def _scan_function(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    file_path: str,
    file_imports: set[str],
    file_alias_map: dict[str, str],
    content: str = "",
) -> list[Capability]:
    """Scan a single function for dangerous capabilities."""
    capabilities: list[Capability] = []
    func_name = func_node.name

    # Collect local imports
    local_imports: set[str] = set()
    local_alias_map: dict[str, str] = {}
    _collect_imports(func_node.body, local_imports, local_alias_map)

    known_imports = file_imports | local_imports
    alias_map = {**file_alias_map, **local_alias_map}

    # Build var_origin
    var_origin = _build_var_origin(func_node, known_imports, alias_map)

    # Track emitted capabilities to avoid exact duplicates per function
    emitted: set[str] = set()

    def _emit(kind: str, confidence: Confidence, line: int, evidence: str,
              library: str, trust: TrustLevel, call_node: ast.Call | None = None) -> None:
        key = f"{kind}:{library}:{func_name}"
        if key in emitted:
            return
        emitted.add(key)

        err_handling = _has_error_handling(func_node, line)
        timeout = False
        if call_node and kind == "outbound" and library in HTTP_LIBRARIES:
            timeout = _has_timeout(call_node)

        input_val = False
        if kind == "financial":
            input_val = _has_input_validation(func_node)

        capabilities.append(Capability(
            kind=kind,
            confidence=confidence,
            function_name=func_name,
            source_file=file_path,
            line_number=line,
            evidence=evidence,
            library=library,
            trust_level=trust,
            has_error_handling=err_handling,
            has_timeout=timeout,
            has_input_validation=input_val,
            call_text=_get_source_line(content, line) if content else "",
        ))

    # Walk all call nodes
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue

        _check_call_node(node, func_name, file_path, known_imports, alias_map,
                         var_origin, func_node, _emit)

    # Check for destructive SQL inside execute() calls
    destructive_results = _check_destructive_sql(func_node, known_imports,
                                                 alias_map, var_origin)
    for line, evidence, conf in destructive_results:
        _emit("destructive", conf, line, evidence, _first_db_import(known_imports),
              TrustLevel.INTERNAL)

    # Check for PROBABLE destructive (SQL keyword in function body but not in execute())
    _check_probable_destructive(func_node, known_imports, file_path, func_name,
                                destructive_results, _emit)

    return capabilities


def _check_probable_destructive(
    func_node: ast.AST,
    known_imports: set[str],
    file_path: str,
    func_name: str,
    confirmed_destructive: list[tuple[int, str, Confidence]],
    _emit: Any,
) -> None:
    """Check for PROBABLE destructive SQL in string literals not inside confirmed execute()."""
    if not _first_db_import(known_imports):
        return
    if confirmed_destructive:
        return

    # Search all string constants in function body
    for node in ast.walk(func_node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            upper = node.value.upper()
            for keyword in DESTRUCTIVE_SQL_KEYWORDS:
                if keyword in upper:
                    _emit("destructive", Confidence.PROBABLE, node.lineno,
                          f"String contains {keyword} (not in confirmed execute())",
                          _first_db_import(known_imports), TrustLevel.INTERNAL)
                    return


def _check_call_node(
    node: ast.Call,
    func_name: str,
    file_path: str,
    known_imports: set[str],
    alias_map: dict[str, str],
    var_origin: dict[str, str],
    func_node: ast.AST,
    _emit: Any,
) -> None:
    """Check a single call node for dangerous capabilities."""
    func = node.func

    # Check builtins: exec(), eval()
    if isinstance(func, ast.Name) and func.id in CODE_EXEC_BUILTINS:
        _emit("code_exec", Confidence.CONFIRMED, node.lineno,
              f"{func.id}() call", func.id, TrustLevel.PRIVILEGED, node)
        return

    # Check simple Name() calls (from X import Y -> Y())
    # Constructors like WebClient() are tracked via var_origin, not emitted as capabilities.
    # Only emit if the call itself is a dangerous action, not just instantiation.
    if isinstance(func, ast.Name):
        return

    # Check attribute calls: obj.method()
    if isinstance(func, ast.Attribute):
        method = func.attr
        obj_name = ""

        if isinstance(func.value, ast.Name):
            obj_name = func.value.id
        elif isinstance(func.value, ast.Attribute):
            obj_name = _get_root_name(func.value)

        if not obj_name:
            return

        # Resolve confidence
        conf, origin = _resolve_confidence(obj_name, method, known_imports,
                                           alias_map, var_origin)

        if conf == Confidence.CONFIRMED and origin:
            _classify_confirmed_call(origin, obj_name, method, node, conf, _emit)
        elif conf == Confidence.HEURISTIC:
            # Only emit heuristic for known dangerous method names
            _classify_heuristic_call(method, node, _emit)

        # Check for shell=True on subprocess calls
        if origin in CODE_EXEC_FUNCTIONS and method in CODE_EXEC_FUNCTIONS.get(origin, []):
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in node.keywords
            )
            if shell_true:
                # Already emitted code_exec, shell=True is just extra evidence
                pass


def _classify_by_origin(
    origin: str, name: str, method: str, node: ast.Call,
    known_imports: set[str], alias_map: dict[str, str],
    var_origin: dict[str, str], _emit: Any,
) -> None:
    """Classify a call by its resolved origin module."""
    if _is_financial_import(origin):
        _emit("financial", Confidence.CONFIRMED, node.lineno,
              f"import {origin} -> {name}()", origin, TrustLevel.RESTRICTED, node)
    elif _is_outbound_import(origin):
        _emit("outbound", Confidence.CONFIRMED, node.lineno,
              f"import {origin} -> {name}()", origin, TrustLevel.EXTERNAL, node)
    elif _is_data_access_import(origin):
        _emit("data_access", Confidence.CONFIRMED, node.lineno,
              f"import {origin} -> {name}()", origin, TrustLevel.INTERNAL, node)


def _classify_confirmed_call(
    origin: str, obj_name: str, method: str,
    node: ast.Call, conf: Confidence, _emit: Any,
) -> None:
    """Classify a confirmed obj.method() call by its origin module."""
    # Code execution
    if origin in CODE_EXEC_FUNCTIONS:
        if method in CODE_EXEC_FUNCTIONS[origin]:
            shell_evidence = ""
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in node.keywords
            )
            if shell_true:
                shell_evidence = ", shell=True"
            _emit("code_exec", conf, node.lineno,
                  f"{origin}.{method}(){shell_evidence}", origin,
                  TrustLevel.PRIVILEGED, node)
            return

    # Financial (check before outbound - stripe is in both)
    if _is_financial_import(origin) and method in OUTBOUND_METHODS:
        _emit("financial", conf, node.lineno,
              f"import {origin} -> {obj_name}.{method}()", origin,
              TrustLevel.RESTRICTED, node)
        return

    # Outbound
    if _is_outbound_import(origin) and method in OUTBOUND_METHODS:
        _emit("outbound", conf, node.lineno,
              f"import {origin} -> {obj_name}.{method}()", origin,
              TrustLevel.EXTERNAL, node)
        return

    # Data access
    if _is_data_access_import(origin) and method in DATA_ACCESS_METHODS:
        _emit("data_access", conf, node.lineno,
              f"import {origin} -> {obj_name}.{method}()", origin,
              TrustLevel.INTERNAL, node)
        return

    # Destructive method on DB object
    if _is_data_access_import(origin) and method in DESTRUCTIVE_METHODS:
        _emit("destructive", conf, node.lineno,
              f"import {origin} -> {obj_name}.{method}()", origin,
              TrustLevel.INTERNAL, node)
        return

    # Data access connect()
    if _is_data_access_import(origin) and method == "connect":
        _emit("data_access", conf, node.lineno,
              f"import {origin} -> {obj_name}.{method}()", origin,
              TrustLevel.INTERNAL, node)
        return


def _classify_heuristic_call(method: str, node: ast.Call, _emit: Any) -> None:
    """Classify an unresolved method call as HEURISTIC (only for known dangerous methods)."""
    # We do NOT emit heuristic for most methods to avoid noise
    # Only emit for very specific dangerous patterns
    pass


def _detect_guardrails(
    tree: ast.Module, file_path: str, content: str,
) -> list[GuardrailSignal]:
    """Detect guardrail signals in a Python file."""
    guardrails: list[GuardrailSignal] = []

    for node in ast.walk(tree):
        # LangGraph HITL: interrupt_before / interrupt_after
        if isinstance(node, ast.keyword):
            if node.arg in ("interrupt_before", "interrupt_after"):
                tools = _extract_list_strings(node.value)
                guardrails.append(GuardrailSignal(
                    kind="hitl",
                    source_file=file_path,
                    line_number=getattr(node, "lineno", 0),
                    detail=node.arg,
                    covers_tools=tools,
                ))

        # Import-based guardrails
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            module = ""
            if isinstance(node, ast.ImportFrom) and node.module:
                module = node.module
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name

            if "guardrails" in module and "nemo" not in module.lower():
                has_usage = _check_guardrail_usage(content)
                guardrails.append(GuardrailSignal(
                    kind="output_filter",
                    source_file=file_path,
                    line_number=node.lineno,
                    detail="guardrails library",
                    has_usage=has_usage,
                ))
            elif "nemoguardrails" in module:
                guardrails.append(GuardrailSignal(
                    kind="input_filter",
                    source_file=file_path,
                    line_number=node.lineno,
                    detail="NeMo Guardrails",
                ))
            elif "llm_guard" in module:
                guardrails.append(GuardrailSignal(
                    kind="output_filter",
                    source_file=file_path,
                    line_number=node.lineno,
                    detail="LLM Guard",
                    has_usage=True,
                ))

            # Check for InputGuardrail / OutputGuardrail
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.name
                    if name == "InputGuardrail":
                        guardrails.append(GuardrailSignal(
                            kind="input_filter",
                            source_file=file_path,
                            line_number=node.lineno,
                            detail="InputGuardrail",
                        ))
                    elif name == "OutputGuardrail":
                        guardrails.append(GuardrailSignal(
                            kind="output_filter",
                            source_file=file_path,
                            line_number=node.lineno,
                            detail="OutputGuardrail",
                            has_usage=True,
                        ))

    # Rate limiting patterns
    if "recursion_limit" in content or "max_iterations" in content or "max_turns" in content:
        guardrails.append(GuardrailSignal(
            kind="rate_limit",
            source_file=file_path,
            line_number=0,
            detail="recursion/iteration limit",
        ))

    # Validation patterns
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id == "isinstance":
                    guardrails.append(GuardrailSignal(
                        kind="validation",
                        source_file=file_path,
                        line_number=node.lineno,
                        detail="isinstance check",
                    ))
                    break
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr in ("model_validate", "TypeAdapter"):
                    guardrails.append(GuardrailSignal(
                        kind="validation",
                        source_file=file_path,
                        line_number=node.lineno,
                        detail=node.func.attr,
                    ))
                    break

    return guardrails


def _check_guardrail_usage(content: str) -> bool:
    """Check if guardrails library has actual usage beyond import."""
    usage_patterns = [".use(", "Guard(", "guard.validate", "guard("]
    return any(pattern in content for pattern in usage_patterns)


def _extract_list_strings(node: ast.expr) -> list[str]:
    """Extract string values from an AST list node."""
    if isinstance(node, ast.List):
        result = []
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                result.append(elt.value)
        return result
    return []


# ── Framework Detection (Layer 1 + Layer 3) ─────────────────────────────────

TRUST_BY_KIND = {
    "data_access": "internal",
    "outbound": "external",
    "code_exec": "privileged",
    "destructive": "internal",
    "financial": "restricted",
    "file_system": "internal",
}


def detect_framework_tools(
    file_imports: set[str],
    alias_map: dict[str, str],
    tree: ast.Module,
    file_path: str,
) -> list[Capability]:
    """Detect capabilities from known framework tool imports and constructor assignments.

    Layer 1: Direct imports of known tools (e.g. from crewai_tools import SerperDevTool).
    Layer 3: Agent(tools=[...]) constructor arguments referencing known tools.
    """
    capabilities: list[Capability] = []
    seen: set[tuple[str, str]] = set()

    # Layer 1: Check alias_map for known tool imports
    for class_name, source_module in alias_map.items():
        if class_name not in KNOWN_TOOLS:
            continue
        profile = KNOWN_TOOLS[class_name]
        # Verify source module matches to prevent false matches on generic names
        source_root = source_module.split(".")[0]
        profile_roots = {m.split(".")[0] for m in profile.source_modules}
        if source_root not in profile_roots:
            continue
        for kind in profile.kinds:
            key = (class_name, kind)
            if key not in seen:
                seen.add(key)
                capabilities.append(Capability(
                    function_name=f"[{class_name}]",
                    kind=kind,
                    library=source_module,
                    confidence=Confidence.CONFIRMED,
                    source_file=file_path,
                    line_number=0,
                    evidence=f"{class_name} (framework tool)",
                    trust_level=TrustLevel(TRUST_BY_KIND.get(kind, "external")),
                    has_error_handling=False,
                    has_timeout=False,
                    call_text=f"{class_name} (framework tool)",
                ))

    # Layer 3: Agent constructor tools=[...] analysis
    agent_constructors = {"Agent", "AssistantAgent", "UserProxyAgent", "ReActAgent"}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        constructor_name = ""
        if isinstance(node.func, ast.Name):
            constructor_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            constructor_name = node.func.attr

        if constructor_name not in agent_constructors:
            continue

        for keyword in node.keywords:
            if keyword.arg == "tools" and isinstance(keyword.value, ast.List):
                for elt in keyword.value.elts:
                    tool_class_name = _extract_tool_class_name(elt)
                    if tool_class_name and tool_class_name in KNOWN_TOOLS:
                        profile = KNOWN_TOOLS[tool_class_name]
                        for kind in profile.kinds:
                            key = (tool_class_name, kind)
                            if key not in seen:
                                seen.add(key)
                                capabilities.append(Capability(
                                    function_name=f"[{constructor_name}.tools -> {tool_class_name}]",
                                    kind=kind,
                                    library=profile.source_modules[0] if profile.source_modules else "unknown",
                                    confidence=Confidence.CONFIRMED,
                                    source_file=file_path,
                                    line_number=node.lineno,
                                    evidence=f"{tool_class_name} assigned to {constructor_name}",
                                    trust_level=TrustLevel(TRUST_BY_KIND.get(kind, "external")),
                                    has_error_handling=False,
                                    has_timeout=False,
                                    call_text=f"{tool_class_name} assigned to {constructor_name}",
                                ))

            # AutoGen: code_execution_config={...} -> code_exec
            if keyword.arg == "code_execution_config":
                if isinstance(keyword.value, ast.Dict):
                    key = ("code_execution_config", "code_exec")
                    if key not in seen:
                        seen.add(key)
                        capabilities.append(Capability(
                            function_name=f"[{constructor_name}.code_execution_config]",
                            kind="code_exec",
                            library="autogen",
                            confidence=Confidence.CONFIRMED,
                            source_file=file_path,
                            line_number=node.lineno,
                            evidence=f"code_execution_config on {constructor_name}",
                            trust_level=TrustLevel.PRIVILEGED,
                            has_error_handling=False,
                            has_timeout=False,
                            call_text=f"code_execution_config on {constructor_name}",
                        ))

    return capabilities


def _extract_tool_class_name(node: ast.expr) -> str:
    """Extract tool class name from a list element (Call or Name)."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
    elif isinstance(node, ast.Name):
        return node.id
    return ""


def detect_framework_guardrails(
    file_imports: set[str],
    alias_map: dict[str, str],
    tree: ast.Module,
    file_path: str,
) -> list[GuardrailSignal]:
    """Detect guardrails expressed through framework patterns."""
    guardrails: list[GuardrailSignal] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        for keyword in node.keywords:
            # CrewAI: Task(human_input=True) -> HITL
            if keyword.arg == "human_input":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    guardrails.append(GuardrailSignal(
                        kind="hitl",
                        source_file=file_path,
                        line_number=getattr(node, "lineno", 0),
                        detail="CrewAI Task with human_input=True",
                        has_usage=True,
                    ))

            # AutoGen: human_input_mode="ALWAYS" or "TERMINATE" -> HITL
            if keyword.arg == "human_input_mode":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value in ("ALWAYS", "TERMINATE"):
                    guardrails.append(GuardrailSignal(
                        kind="hitl",
                        source_file=file_path,
                        line_number=getattr(node, "lineno", 0),
                        detail=f"AutoGen human_input_mode={keyword.value.value}",
                        has_usage=True,
                    ))

            # Rate limiting: max_rpm, rate_limit
            if keyword.arg in ("max_rpm", "rate_limit", "max_requests_per_minute"):
                guardrails.append(GuardrailSignal(
                    kind="rate_limit",
                    source_file=file_path,
                    line_number=getattr(node, "lineno", 0),
                    detail=f"{keyword.arg} configured",
                    has_usage=True,
                ))

            # Structured output validation
            if keyword.arg in ("result_type", "response_format", "output_pydantic"):
                guardrails.append(GuardrailSignal(
                    kind="validation",
                    source_file=file_path,
                    line_number=getattr(node, "lineno", 0),
                    detail=f"Structured output validation via {keyword.arg}",
                    has_usage=True,
                ))

    # Decorator-based guardrails
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Attribute):
                    if decorator.attr in ("result_validator", "output_validator"):
                        guardrails.append(GuardrailSignal(
                            kind="output_filter",
                            source_file=file_path,
                            line_number=getattr(node, "lineno", 0),
                            detail=f"@{decorator.attr} decorator",
                            has_usage=True,
                        ))

    # Import-based framework guardrails
    framework_guard_classes = {
        "HumanApprovalCallbackHandler": ("hitl", "LangChain HumanApprovalCallbackHandler"),
        "HumanInputRun": ("hitl", "LangChain HumanInputRun"),
    }
    for class_name, (kind, detail) in framework_guard_classes.items():
        if class_name in alias_map:
            guardrails.append(GuardrailSignal(
                kind=kind,
                source_file=file_path,
                line_number=0,
                detail=detail,
                has_usage=True,
            ))

    return guardrails


def detect_framework(file_imports: set[str], alias_map: dict[str, str]) -> set[str]:
    """Detect which agent frameworks the file uses.

    Returns set of framework names (may be empty).
    """
    found: set[str] = set()
    for module, framework_name in AGENT_FRAMEWORK_IMPORTS.items():
        if module in file_imports:
            found.add(framework_name)
            continue
        for alias_source in alias_map.values():
            if alias_source.startswith(module):
                found.add(framework_name)
                break
    return found


# ── Guardrail coverage resolution ──────────────────────────────────────────


def resolve_guardrail_coverage(
    guard: GuardrailSignal,
    ast_trees: dict[str, ast.Module],
    capabilities: list[Capability],
) -> list[str]:
    """Determine which tools a guardrail protects.

    ast_trees: dict of file_path -> ast.Module.
    """
    covered: list[str] = []

    tree = ast_trees.get(guard.source_file)
    if not tree:
        return covered

    if "output_pydantic" in guard.detail or "human_input" in guard.detail:
        # Find Task() call at this line, extract agent= -> get that agent's tools
        task_node = _find_call_at_line(tree, guard.line_number, "Task")
        if task_node:
            agent_name = _extract_agent_keyword(task_node)
            if agent_name:
                covered = _find_agent_tools(tree, agent_name)

    elif "interrupt_before" in guard.detail or "interrupt_after" in guard.detail:
        covered = guard.covers_tools  # Already populated during detection

    elif "isinstance" in guard.detail:
        # Covers capabilities in the same file
        covered = [
            c.function_name for c in capabilities
            if c.source_file == guard.source_file
        ]

    return covered


def _find_call_at_line(tree: ast.Module, line: int, func_name: str) -> ast.Call | None:
    """Find a Call node at a specific line matching func_name."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node, 'lineno', 0) == line:
            if isinstance(node.func, ast.Name) and node.func.id == func_name:
                return node
            if isinstance(node.func, ast.Attribute) and node.func.attr == func_name:
                return node
    # Broader search: within 5 lines
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            node_line = getattr(node, 'lineno', 0)
            if abs(node_line - line) <= 5:
                if isinstance(node.func, ast.Name) and node.func.id == func_name:
                    return node
                if isinstance(node.func, ast.Attribute) and node.func.attr == func_name:
                    return node
    return None


def _extract_agent_keyword(call_node: ast.Call) -> str:
    """Extract the agent= keyword value from a Task() call."""
    for kw in call_node.keywords:
        if kw.arg == "agent":
            if isinstance(kw.value, ast.Name):
                return kw.value.id
            if isinstance(kw.value, ast.Call):
                if isinstance(kw.value.func, ast.Name):
                    return kw.value.func.id
                if isinstance(kw.value.func, ast.Attribute):
                    return kw.value.func.attr
    return ""


def _find_agent_tools(tree: ast.Module, agent_var: str) -> list[str]:
    """Find the tools assigned to an agent variable in the AST."""
    tools: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name != "Agent":
                continue
            for kw in node.keywords:
                if kw.arg == "tools" and isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Call):
                            if isinstance(elt.func, ast.Name):
                                tools.append(elt.func.id)
                            elif isinstance(elt.func, ast.Attribute):
                                tools.append(elt.func.attr)
                        elif isinstance(elt, ast.Name):
                            tools.append(elt.id)
    return tools
