"""Environment variable and hardcoded secret scanner."""
from __future__ import annotations

import logging
import os
import re

from stratum.models import Confidence, Finding, RiskCategory, Severity
from stratum.knowledge.db import SENSITIVE_ENV_PATTERNS

logger = logging.getLogger(__name__)

SECRET_REGEXES = [
    (re.compile(r"sk-[a-zA-Z0-9_-]{20,}"), "OpenAI API key"),
    (re.compile(r"sk_live_[a-zA-Z0-9]+"), "Stripe live secret key"),
    (re.compile(r"Bearer [a-zA-Z0-9_-]{20,}"), "Bearer token"),
    (re.compile(r"postgresql://[^:]+:[^@]+@"), "PostgreSQL connection string with password"),
    (re.compile(r"mongodb://[^:]+:[^@]+@"), "MongoDB connection string with password"),
]


def scan_env(directory: str, py_file_paths: list[str]) -> tuple[list[str], list[Finding]]:
    """Scan for env var exposure. Returns (env_var_names, findings)."""
    env_var_names: list[str] = []
    findings: list[Finding] = []

    # Find .env files
    env_files = _find_env_files(directory)
    for env_path in env_files:
        names = _parse_env_file(env_path)
        env_var_names.extend(names)

    # Check if .env is in .gitignore
    if env_files:
        gitignore_path = os.path.join(directory, ".gitignore")
        env_in_gitignore = _is_env_in_gitignore(gitignore_path)
        if not env_in_gitignore:
            findings.append(Finding(
                id="ENV-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category=RiskCategory.SECURITY,
                title=".env not in .gitignore",
                path=".env file found without .gitignore protection",
                description="The .env file containing secrets is not listed in .gitignore. "
                            "It may be committed to version control, exposing credentials.",
                evidence=[f"{os.path.basename(f)}" for f in env_files],
                scenario="A developer commits .env to git. Anyone with repo access "
                         "sees production database credentials and API keys.",
                remediation='echo ".env" >> .gitignore',
                effort="low",
                owasp_id="ASI04",
                quick_fix_type="env_gitignore",
            ))

    # Scan .py files for hardcoded secrets
    for py_path in py_file_paths:
        try:
            with open(py_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            continue
        _scan_for_secrets(py_path, content, directory, findings)

    return env_var_names, findings


def _find_env_files(directory: str) -> list[str]:
    """Find .env files in the directory."""
    env_files: list[str] = []
    try:
        for entry in os.listdir(directory):
            if entry == ".env" or entry.startswith(".env."):
                full = os.path.join(directory, entry)
                if os.path.isfile(full):
                    env_files.append(full)
    except OSError:
        pass
    return env_files


def _parse_env_file(env_path: str) -> list[str]:
    """Parse a .env file and return variable names."""
    names: list[str] = []
    try:
        with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    name = line.split("=", 1)[0].strip()
                    if name:
                        names.append(name)
    except OSError:
        pass
    return names


def _is_env_in_gitignore(gitignore_path: str) -> bool:
    """Check if .env is listed in .gitignore."""
    try:
        with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line in (".env", ".env*", ".env.*", "*.env"):
                    return True
    except OSError:
        pass
    return False


def _scan_for_secrets(
    file_path: str, content: str, base_dir: str, findings: list[Finding],
) -> None:
    """Scan Python file content for hardcoded secrets."""
    rel_path = os.path.relpath(file_path, base_dir)
    for regex, secret_type in SECRET_REGEXES:
        for match in regex.finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(
                id="ENV-002",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category=RiskCategory.SECURITY,
                title=f"Hardcoded {secret_type}",
                path=f"{rel_path}:{line_num} contains hardcoded {secret_type}",
                description=f"A {secret_type} is hardcoded in source code. "
                            "Use environment variables instead.",
                evidence=[f"{rel_path}:{line_num}"],
                scenario=f"The {secret_type} is exposed when the repository is shared or leaked.",
                remediation=f'Use os.environ["{secret_type.upper().replace(" ", "_")}"] instead',
                effort="low",
                owasp_id="ASI04",
            ))
            break  # One finding per regex per file
