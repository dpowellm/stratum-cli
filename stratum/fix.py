"""Auto-remediation: AST-based fixes for common AI agent security issues.

Auto-fixable findings:
  STRATUM-001, BR01  -> add human_input=True (CrewAI) / interrupt_before (LangGraph)
  STRATUM-002        -> same, applied to destructive tools
  STRATUM-008        -> wrap unhandled external calls in try/except
  STRATUM-010        -> add memory=True to CrewAI Crew()
  STRATUM-009        -> add timeout=30 to requests/httpx calls

Not auto-fixable (requires developer judgment):
  CR05, CR06, CR06.1 -> architectural, developer must decide
  CR01, CR02         -> architectural

Output modes:
  apply_fixes()     -> modifies files in place (--fix)
  generate_patch()  -> returns unified diff without modifying files (--patch-output)
"""
from __future__ import annotations

import ast
import difflib
import os
from dataclasses import dataclass, field


# Finding IDs that can be auto-fixed (v4)
AUTO_FIXABLE = {"STRATUM-001", "STRATUM-002", "STRATUM-BR01", "STRATUM-008", "STRATUM-009", "STRATUM-010"}


@dataclass
class FixResult:
    """Result of applying a single fix to a file."""
    file_path: str
    finding_id: str
    fix_type: str
    description: str
    count: int = 0


@dataclass
class PatchFix:
    """A fix represented as original + fixed content for diff generation."""
    finding_id: str
    file_path: str
    original: str
    fixed: str
    description: str


def apply_fixes(result, project_path: str) -> list[FixResult]:
    """Apply all auto-fixable remediations by modifying files in place.

    Supports:
    - add_hitl: Add human_input=True to CrewAI Task() constructors
    - add_interrupt: Add interrupt_before to LangGraph compile() calls
    - add_memory: Add memory=True to CrewAI Crew() constructors
    - add_timeout: Add timeout=30 to requests/httpx calls
    """
    all_fixes: list[FixResult] = []

    py_files = _collect_python_files(result, project_path)
    all_findings = result.top_paths + result.signals
    frameworks = getattr(result, "detected_frameworks", [])

    needs_hitl = any(f.id in ("STRATUM-001", "STRATUM-002", "STRATUM-BR01") for f in all_findings)
    needs_memory = any(f.id == "STRATUM-010" for f in all_findings)
    needs_timeout = any(f.id == "STRATUM-009" for f in all_findings)
    needs_error_handling = any(f.id == "STRATUM-008" for f in all_findings)

    for file_path in sorted(py_files):
        if needs_hitl:
            if "CrewAI" in frameworks:
                fix = _apply_hitl_fix(file_path, project_path)
                if fix:
                    all_fixes.append(fix)
            if "LangGraph" in frameworks:
                fix = _apply_interrupt_fix(file_path, project_path)
                if fix:
                    all_fixes.append(fix)

        if needs_memory:
            fix = _apply_memory_fix(file_path, project_path)
            if fix:
                all_fixes.append(fix)

        if needs_timeout:
            fix = _apply_timeout_fix(file_path, project_path)
            if fix:
                all_fixes.append(fix)

        if needs_error_handling:
            fix = _apply_error_handling_fix(file_path, project_path)
            if fix:
                all_fixes.append(fix)

    return all_fixes


def generate_patch(result, project_path: str) -> list[PatchFix]:
    """Generate fixes as diffs without modifying source files.

    Returns a list of PatchFix objects that can be written as a unified diff.
    """
    all_patches: list[PatchFix] = []

    py_files = _collect_python_files(result, project_path)
    all_findings = result.top_paths + result.signals
    frameworks = getattr(result, "detected_frameworks", [])

    needs_hitl = any(f.id in ("STRATUM-001", "STRATUM-002", "STRATUM-BR01") for f in all_findings)
    needs_memory = any(f.id == "STRATUM-010" for f in all_findings)
    needs_timeout = any(f.id == "STRATUM-009" for f in all_findings)
    needs_error_handling = any(f.id == "STRATUM-008" for f in all_findings)

    for file_path in sorted(py_files):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                original = f.read()
        except OSError:
            continue

        current = original

        if needs_hitl and "CrewAI" in frameworks:
            current = _transform_add_keyword(current, "Task", "human_input", "True")

        if needs_hitl and "LangGraph" in frameworks:
            current = _transform_add_interrupt_before(current)

        if needs_memory:
            current = _transform_add_keyword(current, "Crew", "memory", "True")

        if needs_timeout:
            current = _transform_add_timeout(current)

        if needs_error_handling:
            current = _transform_wrap_try_except(current)

        if current != original:
            rel_path = os.path.relpath(file_path, project_path)
            all_patches.append(PatchFix(
                finding_id="auto-fix",
                file_path=rel_path,
                original=original,
                fixed=current,
                description=f"Auto-fix applied to {rel_path}",
            ))

    return all_patches


def write_patch_file(patches: list[PatchFix], output_path: str) -> None:
    """Write a unified diff .patch file from a list of PatchFix objects."""
    with open(output_path, "w", encoding="utf-8") as f:
        for patch in patches:
            diff = difflib.unified_diff(
                patch.original.splitlines(keepends=True),
                patch.fixed.splitlines(keepends=True),
                fromfile=f"a/{patch.file_path}",
                tofile=f"b/{patch.file_path}",
            )
            f.writelines(diff)
            f.write("\n")


def count_fixable_findings(result) -> int:
    """Count how many findings are auto-fixable."""
    all_findings = result.top_paths + result.signals
    return sum(1 for f in all_findings if f.id in AUTO_FIXABLE)


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

def _collect_python_files(result, project_path: str) -> set[str]:
    """Collect Python files from capabilities and finding evidence."""
    py_files: set[str] = set()
    for cap in result.capabilities:
        abs_file = os.path.join(project_path, cap.source_file)
        if os.path.isfile(abs_file) and abs_file.endswith(".py"):
            py_files.add(abs_file)

    all_findings = result.top_paths + result.signals
    for finding in all_findings:
        for ev in finding.evidence:
            parts = ev.split(":")
            file_part = parts[0]
            abs_file = os.path.join(project_path, file_part)
            if os.path.isfile(abs_file) and abs_file.endswith(".py"):
                py_files.add(abs_file)

    # Also walk project for .py files if we found very few
    if len(py_files) < 2:
        for root, _dirs, files in os.walk(project_path):
            if ".git" in root or "__pycache__" in root:
                continue
            for fname in files:
                if fname.endswith(".py"):
                    py_files.add(os.path.join(root, fname))

    return py_files


# ---------------------------------------------------------------------------
# CrewAI fixes
# ---------------------------------------------------------------------------

def _apply_hitl_fix(file_path: str, project_path: str) -> FixResult | None:
    """Add human_input=True to Task() constructor calls."""
    return _add_keyword_to_call(
        file_path=file_path,
        project_path=project_path,
        call_name="Task",
        keyword_name="human_input",
        keyword_value="True",
        finding_id="STRATUM-001",
        fix_type="add_hitl",
        description="Added human_input=True to Task constructors",
    )


def _apply_memory_fix(file_path: str, project_path: str) -> FixResult | None:
    """Add memory=True to Crew() constructor calls."""
    return _add_keyword_to_call(
        file_path=file_path,
        project_path=project_path,
        call_name="Crew",
        keyword_name="memory",
        keyword_value="True",
        finding_id="STRATUM-010",
        fix_type="add_memory",
        description="Added memory=True to Crew constructor",
    )


# ---------------------------------------------------------------------------
# LangGraph fixes
# ---------------------------------------------------------------------------

def _apply_interrupt_fix(file_path: str, project_path: str) -> FixResult | None:
    """Add or extend interrupt_before on LangGraph compile() calls."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
    except OSError:
        return None

    if ".compile(" not in source:
        return None

    fixed = _transform_add_interrupt_before(source)
    if fixed == source:
        return None

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(fixed)

    rel_path = os.path.relpath(file_path, project_path)
    return FixResult(
        file_path=rel_path,
        finding_id="STRATUM-001",
        fix_type="add_interrupt",
        description="Added interrupt_before to compile() call",
        count=1,
    )


def _transform_add_interrupt_before(source: str) -> str:
    """Transform source to add interrupt_before to compile() calls.

    Finds graph.compile() calls and:
    - If interrupt_before already exists, leaves it alone
    - If not, collects node names from add_node() calls and adds them
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    # Find all node names from add_node calls
    node_names: list[str] = []
    compile_calls: list[tuple[int, int]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue

        if node.func.attr == "add_node" and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                node_names.append(arg.value)

        if node.func.attr == "compile":
            # Check if interrupt_before already present
            has_ib = any(kw.arg == "interrupt_before" for kw in node.keywords)
            if not has_ib and node.end_lineno and node.end_col_offset:
                compile_calls.append((node.end_lineno - 1, node.end_col_offset - 1))

    if not compile_calls or not node_names:
        return source

    # Only interrupt before nodes that have outbound capabilities
    # For simplicity, use all non-start nodes
    interrupt_nodes = node_names[:3]  # Cap at 3

    lines = source.splitlines(keepends=True)
    for line_idx, col_idx in reversed(compile_calls):
        if line_idx >= len(lines):
            continue
        line = lines[line_idx]
        if col_idx >= len(line) or line[col_idx] != ")":
            continue

        before = line[:col_idx]
        ib_value = repr(interrupt_nodes)
        if before.strip() == "":
            # Multi-line: insert new line before closing paren
            prev_line = lines[line_idx - 1] if line_idx > 0 else ""
            indent = " " * (len(prev_line) - len(prev_line.lstrip()))
            lines.insert(line_idx, f"{indent}interrupt_before={ib_value},\n")
        else:
            stripped = before.rstrip()
            if stripped.endswith(","):
                lines[line_idx] = line[:col_idx] + f" interrupt_before={ib_value}" + line[col_idx:]
            else:
                lines[line_idx] = line[:col_idx] + f", interrupt_before={ib_value}" + line[col_idx:]

    return "".join(lines)


# ---------------------------------------------------------------------------
# Timeout fixes
# ---------------------------------------------------------------------------

def _apply_timeout_fix(file_path: str, project_path: str) -> FixResult | None:
    """Add timeout=30 to requests.get/post/etc calls without timeout."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
    except OSError:
        return None

    if "requests." not in source and "httpx." not in source:
        return None

    fixed = _transform_add_timeout(source)
    if fixed == source:
        return None

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(fixed)

    rel_path = os.path.relpath(file_path, project_path)
    return FixResult(
        file_path=rel_path,
        finding_id="STRATUM-009",
        fix_type="add_timeout",
        description="Added timeout=30 to HTTP calls",
        count=1,
    )


def _transform_add_timeout(source: str) -> str:
    """Transform source to add timeout=30 to requests/httpx calls."""
    HTTP_METHODS = {
        "requests.get", "requests.post", "requests.put",
        "requests.delete", "requests.patch", "requests.head",
        "httpx.get", "httpx.post", "httpx.put",
        "httpx.delete", "httpx.patch",
    }

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    insertions: list[tuple[int, int]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name):
            continue

        call_name = f"{node.func.value.id}.{node.func.attr}"
        if call_name not in HTTP_METHODS:
            continue

        if any(kw.arg == "timeout" for kw in node.keywords):
            continue

        if node.end_lineno and node.end_col_offset:
            insertions.append((node.end_lineno - 1, node.end_col_offset - 1))

    if not insertions:
        return source

    lines = source.splitlines(keepends=True)
    for line_idx, col_idx in reversed(insertions):
        if line_idx >= len(lines):
            continue
        line = lines[line_idx]
        if col_idx >= len(line) or line[col_idx] != ")":
            continue

        before = line[:col_idx]
        if before.strip() == "":
            prev_line = lines[line_idx - 1] if line_idx > 0 else ""
            indent = " " * (len(prev_line) - len(prev_line.lstrip()))
            lines.insert(line_idx, f"{indent}timeout=30,\n")
        else:
            stripped = before.rstrip()
            if stripped.endswith(","):
                lines[line_idx] = line[:col_idx] + " timeout=30" + line[col_idx:]
            else:
                lines[line_idx] = line[:col_idx] + ", timeout=30" + line[col_idx:]

    return "".join(lines)


# ---------------------------------------------------------------------------
# Generic keyword insertion (used by CrewAI fixes)
# ---------------------------------------------------------------------------

def _transform_add_keyword(source: str, call_name: str, kw_name: str, kw_value: str) -> str:
    """Transform source to add a keyword to all calls of a given name."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    insertions: list[tuple[int, int, int]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name != call_name:
            continue
        if any(kw.arg == kw_name for kw in node.keywords):
            continue
        if node.end_lineno is not None and node.end_col_offset is not None:
            insertions.append((node.end_lineno - 1, node.end_col_offset - 1, node.col_offset))

    if not insertions:
        return source

    lines = source.splitlines(keepends=True)
    for line_idx, col_idx, _call_col in reversed(sorted(insertions)):
        if line_idx >= len(lines):
            continue
        line = lines[line_idx]
        if col_idx >= len(line) or line[col_idx] != ")":
            continue

        before = line[:col_idx]
        if before.strip() == "":
            prev_line = lines[line_idx - 1] if line_idx > 0 else ""
            indent = " " * (len(prev_line) - len(prev_line.lstrip()))
            lines.insert(line_idx, f"{indent}{kw_name}={kw_value},\n")
        else:
            stripped = before.rstrip()
            if stripped.endswith(","):
                lines[line_idx] = line[:col_idx] + f" {kw_name}={kw_value}" + line[col_idx:]
            else:
                lines[line_idx] = line[:col_idx] + f", {kw_name}={kw_value}" + line[col_idx:]

    return "".join(lines)


def _add_keyword_to_call(
    file_path: str,
    project_path: str,
    call_name: str,
    keyword_name: str,
    keyword_value: str,
    finding_id: str,
    fix_type: str,
    description: str,
) -> FixResult | None:
    """Apply a keyword insertion fix to a file in place."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
    except OSError:
        return None

    fixed = _transform_add_keyword(source, call_name, keyword_name, keyword_value)
    if fixed == source:
        return None

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(fixed)

    # Count changes
    orig_lines = source.splitlines()
    fixed_lines = fixed.splitlines()
    modified_count = sum(1 for a, b in zip(orig_lines, fixed_lines) if a != b)
    modified_count += abs(len(fixed_lines) - len(orig_lines))

    rel_path = os.path.relpath(file_path, project_path)
    return FixResult(
        file_path=rel_path,
        finding_id=finding_id,
        fix_type=fix_type,
        description=f"{description} ({modified_count} change{'s' if modified_count != 1 else ''})",
        count=modified_count,
    )


# ---------------------------------------------------------------------------
# Error handling fixes (STRATUM-008)
# ---------------------------------------------------------------------------

# External call patterns to detect for try/except wrapping
_EXTERNAL_CALL_MODULES = {"requests", "httpx", "urllib"}
_EXTERNAL_CALL_METHODS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.patch",
}


def _apply_error_handling_fix(file_path: str, project_path: str) -> FixResult | None:
    """Wrap unhandled external calls in try/except blocks."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
    except OSError:
        return None

    if not any(mod in source for mod in _EXTERNAL_CALL_MODULES):
        return None

    fixed = _transform_wrap_try_except(source)
    if fixed == source:
        return None

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(fixed)

    orig_lines = source.splitlines()
    fixed_lines = fixed.splitlines()
    wrapped_count = len(fixed_lines) - len(orig_lines)

    rel_path = os.path.relpath(file_path, project_path)
    return FixResult(
        file_path=rel_path,
        finding_id="STRATUM-008",
        fix_type="add_error_handling",
        description=f"Wrapped external calls in try/except ({wrapped_count} lines added)",
        count=max(1, wrapped_count // 3),
    )


def _transform_wrap_try_except(source: str) -> str:
    """AST-based transform: wrap function bodies containing unhandled external calls.

    Strategy:
    1. Parse AST, find FunctionDef nodes
    2. For each function, check if it contains requests/httpx calls
    3. If those calls are NOT already inside a try/except, wrap the entire body
    4. Return string with error message instead of crashing
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    # Find functions that need wrapping
    functions_to_wrap: list[tuple[int, int, int]] = []  # (start_line, end_line, indent)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Check if function body contains external calls
        has_external_call = False
        is_already_wrapped = False

        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                if isinstance(child.func.value, ast.Name):
                    call_name = f"{child.func.value.id}.{child.func.attr}"
                    if call_name in _EXTERNAL_CALL_METHODS:
                        has_external_call = True

        # Check if the function body is already wrapped in try/except
        if node.body and isinstance(node.body[0], ast.Try):
            is_already_wrapped = True

        if has_external_call and not is_already_wrapped and node.body:
            first_stmt = node.body[0]
            last_stmt = node.body[-1]
            body_start = first_stmt.lineno  # 1-indexed
            body_end = getattr(last_stmt, 'end_lineno', last_stmt.lineno)
            # Get indentation from the first body line
            body_indent = first_stmt.col_offset
            functions_to_wrap.append((body_start, body_end, body_indent))

    if not functions_to_wrap:
        return source

    lines = source.splitlines(keepends=True)

    # Process in reverse order to maintain line numbers
    for body_start, body_end, body_indent in reversed(sorted(functions_to_wrap)):
        indent = " " * body_indent
        inner_indent = indent + "    "

        # Indent existing body lines by one extra level
        for i in range(body_start - 1, min(body_end, len(lines))):
            if lines[i].strip():  # Don't indent empty lines
                lines[i] = "    " + lines[i]

        # Insert try: before body
        lines.insert(body_start - 1, f"{indent}try:\n")

        # Insert except block after body (account for the inserted try: line)
        except_line = body_end + 1  # +1 for the try: line we inserted
        except_block = (
            f"{indent}except Exception as e:\n"
            f"{inner_indent}return f\"Tool error: {{type(e).__name__}}: {{e}}\"\n"
        )
        lines.insert(except_line, except_block)

    return "".join(lines)
