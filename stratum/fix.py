"""Auto-remediation: AST-based fixes for common AI agent security issues."""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field


@dataclass
class FixResult:
    """Result of applying a single fix to a file."""
    file_path: str
    finding_id: str
    fix_type: str
    description: str
    count: int = 0


def apply_fixes(result, project_path: str) -> list[FixResult]:
    """Apply all auto-fixable remediations based on scan findings.

    Currently supports:
    - add_hitl: Add human_input=True to CrewAI Task() constructors
    - add_memory: Add memory=True to CrewAI Crew() constructors
    """
    all_fixes: list[FixResult] = []

    # Collect Python files from capabilities
    py_files: set[str] = set()
    for cap in result.capabilities:
        abs_file = os.path.join(project_path, cap.source_file)
        if os.path.isfile(abs_file) and abs_file.endswith(".py"):
            py_files.add(abs_file)

    # Also check evidence from findings
    all_findings = result.top_paths + result.signals
    for finding in all_findings:
        for ev in finding.evidence:
            parts = ev.split(":")
            file_part = parts[0]
            abs_file = os.path.join(project_path, file_part)
            if os.path.isfile(abs_file) and abs_file.endswith(".py"):
                py_files.add(abs_file)

    # Check which fix types are needed
    needs_hitl = any(f.id == "STRATUM-001" for f in all_findings)
    needs_memory = any(f.id == "STRATUM-010" for f in all_findings)

    for file_path in sorted(py_files):
        if needs_hitl:
            fix = _apply_hitl_fix(file_path, project_path)
            if fix:
                all_fixes.append(fix)

        if needs_memory:
            fix = _apply_memory_fix(file_path, project_path)
            if fix:
                all_fixes.append(fix)

    return all_fixes


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
    """Generic: add a keyword argument to all calls of a given name in a file.

    Uses AST for detection and targeted string insertion to preserve formatting.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
    except OSError:
        return None

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    lines = source.splitlines(keepends=True)
    # Find all Call nodes matching call_name that lack the keyword
    # Store (end_line_idx, end_col_idx, start_col_offset) for each
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

        # Check if keyword already present
        if any(kw.arg == keyword_name for kw in node.keywords):
            continue

        # Record the end position for insertion
        if node.end_lineno is not None and node.end_col_offset is not None:
            insertions.append((
                node.end_lineno - 1,
                node.end_col_offset - 1,
                node.col_offset,
            ))

    if not insertions:
        return None

    # Apply insertions in reverse order to preserve line numbers
    insertions.sort(reverse=True)
    modified_count = 0
    for line_idx, col_idx, call_col in insertions:
        line = lines[line_idx]
        if col_idx >= len(line) or line[col_idx] != ")":
            continue

        before_paren = line[:col_idx]
        is_paren_on_own_line = before_paren.strip() == ""

        if is_paren_on_own_line:
            # Multi-line call: insert new keyword line before closing paren
            # Match indentation of the previous argument line
            prev_line = lines[line_idx - 1] if line_idx > 0 else ""
            prev_indent = len(prev_line) - len(prev_line.lstrip())
            indent = " " * prev_indent
            new_line = f"{indent}{keyword_name}={keyword_value},\n"
            lines.insert(line_idx, new_line)
        else:
            # Single-line or last arg on same line as paren
            # Check for trailing comma before paren
            stripped = before_paren.rstrip()
            if stripped.endswith(","):
                insert_text = f" {keyword_name}={keyword_value}"
            else:
                insert_text = f", {keyword_name}={keyword_value}"
            lines[line_idx] = line[:col_idx] + insert_text + line[col_idx:]

        modified_count += 1

    if modified_count == 0:
        return None

    # Write back
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("".join(lines))

    rel_path = os.path.relpath(file_path, project_path)
    return FixResult(
        file_path=rel_path,
        finding_id=finding_id,
        fix_type=fix_type,
        description=f"{description} ({modified_count} call{'s' if modified_count != 1 else ''})",
        count=modified_count,
    )
