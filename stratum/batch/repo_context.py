"""RepoContext builder for GitHub batch scan pipeline.

Enriches scan profiles with repository metadata and domain inference.
"""
from __future__ import annotations

import hashlib
import os
import re

from stratum.models import RepoContext


DOMAIN_KEYWORDS: dict[str, list[str]] = {
    "finance": [
        "trading", "portfolio", "SEC", "financial", "investment",
        "stock", "fund", "banking", "fintech", "payment", "accounting",
    ],
    "hr": [
        "recruitment", "hiring", "candidate", "resume", "CV",
        "job posting", "onboarding", "employee", "HR",
    ],
    "marketing": [
        "marketing", "campaign", "content", "SEO", "social media",
        "brand", "advertising", "lead gen",
    ],
    "customer_support": [
        "support", "ticket", "helpdesk", "customer service",
        "chatbot", "FAQ", "complaint",
    ],
    "devops": [
        "deployment", "CI/CD", "monitoring", "infrastructure",
        "Docker", "Kubernetes", "DevOps",
    ],
    "research": [
        "research", "analysis", "paper", "academic",
        "literature", "survey",
    ],
    "legal": [
        "legal", "contract", "compliance", "regulation",
        "policy", "terms",
    ],
    "healthcare": [
        "patient", "diagnosis", "medical", "health",
        "clinical", "HIPAA",
    ],
}


def infer_domain(
    readme_text: str, repo_name: str, description: str
) -> tuple[str, float, list[str]]:
    """Infer project domain from text signals.

    Returns (domain, confidence, matching_signals).
    """
    text = f"{readme_text} {repo_name} {description}".lower()

    scores: dict[str, int] = {}
    signals: dict[str, list[str]] = {}
    for domain, keywords in DOMAIN_KEYWORDS.items():
        matches = [kw for kw in keywords if kw.lower() in text]
        if matches:
            scores[domain] = len(matches)
            signals[domain] = matches

    if not scores:
        return ("general", 0.0, [])

    best = max(scores, key=scores.get)  # type: ignore[arg-type]
    confidence = min(1.0, scores[best] / 3.0)
    return (best, confidence, signals[best])


def build_repo_context(repo_info: dict, clone_dir: str) -> RepoContext:
    """Build a RepoContext from GitHub API data and a cloned directory.

    Args:
        repo_info: Dict with GitHub API repo fields (full_name, stargazers_count, etc.)
        clone_dir: Path to the cloned repository.
    """
    ctx = RepoContext()

    full_name = repo_info.get("full_name", "")
    ctx.repo_hash = hashlib.sha256(full_name.encode()).hexdigest()[:16]
    ctx.platform = "github"

    ctx.stars = repo_info.get("stargazers_count", 0)
    ctx.forks = repo_info.get("forks_count", 0)
    ctx.watchers = repo_info.get("watchers_count", 0)
    ctx.open_issues = repo_info.get("open_issues_count", 0)

    ctx.created_at = repo_info.get("created_at", "")
    ctx.last_commit_at = repo_info.get("pushed_at", "")
    ctx.contributor_count = repo_info.get("contributors_count", 0)
    ctx.is_archived = repo_info.get("archived", False)
    ctx.primary_language = repo_info.get("language", "")

    ctx.has_tests = _has_tests(clone_dir)
    ctx.has_ci = _has_ci(clone_dir)
    ctx.has_dockerfile = _has_dockerfile(clone_dir)
    ctx.has_requirements_txt = os.path.exists(
        os.path.join(clone_dir, "requirements.txt")
    )
    ctx.has_pyproject_toml = os.path.exists(
        os.path.join(clone_dir, "pyproject.toml")
    )

    # Domain inference from README
    readme = _read_readme(clone_dir)
    ctx.has_readme = bool(readme)
    ctx.readme_length = len(readme)
    if readme:
        readme_lower = readme.lower()
        ctx.readme_mentions_security = any(
            w in readme_lower
            for w in ("security", "vulnerability", "secure", "auth")
        )
        ctx.readme_mentions_production = any(
            w in readme_lower
            for w in ("production", "deploy", "enterprise", "scale")
        )

    ctx.domain_hint, ctx.domain_confidence, ctx.domain_signals = infer_domain(
        readme, repo_info.get("name", ""), repo_info.get("description", "") or ""
    )

    # Dependency versions
    ctx.dependency_versions = _parse_requirements(clone_dir)

    return ctx


def _has_tests(clone_dir: str) -> bool:
    """Check if the project has test files."""
    for root, dirs, files in os.walk(clone_dir):
        if "tests" in dirs or "test" in dirs:
            return True
        for f in files:
            if f.startswith("test_") and f.endswith(".py"):
                return True
    return False


def _has_ci(clone_dir: str) -> bool:
    """Check if the project has CI configuration."""
    ci_paths = [
        os.path.join(clone_dir, ".github", "workflows"),
        os.path.join(clone_dir, ".gitlab-ci.yml"),
        os.path.join(clone_dir, ".circleci"),
        os.path.join(clone_dir, "Jenkinsfile"),
    ]
    return any(os.path.exists(p) for p in ci_paths)


def _has_dockerfile(clone_dir: str) -> bool:
    """Check if the project has a Dockerfile."""
    return os.path.exists(os.path.join(clone_dir, "Dockerfile"))


def _read_readme(clone_dir: str) -> str:
    """Read README content if it exists."""
    for name in ("README.md", "README.rst", "README.txt", "README"):
        path = os.path.join(clone_dir, name)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read(50_000)  # Cap at 50KB
            except OSError:
                pass
    return ""


def _parse_requirements(clone_dir: str) -> dict[str, str]:
    """Parse dependency versions from requirements.txt or pyproject.toml."""
    versions: dict[str, str] = {}

    req_path = os.path.join(clone_dir, "requirements.txt")
    if os.path.exists(req_path):
        try:
            with open(req_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    match = re.match(r"([a-zA-Z0-9_-]+)\s*[=><~!]+\s*([0-9.]+)", line)
                    if match:
                        versions[match.group(1).lower()] = match.group(2)
        except OSError:
            pass

    return versions
