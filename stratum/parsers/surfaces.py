"""Connectable surface detectors: LLM models, env var names, vector stores.

These are piggybacked on the AST walk — no extra file I/O needed.
All detectors operate on pre-parsed ASTs and discovered file lists.
"""
from __future__ import annotations

import ast
import os


# ---------------------------------------------------------------------------
# LLM Model Detection
# ---------------------------------------------------------------------------

MODEL_CLASSES: dict[str, str] = {
    "ChatOpenAI": "openai",
    "AzureChatOpenAI": "azure",
    "ChatAnthropic": "anthropic",
    "ChatGoogleGenerativeAI": "google",
    "Ollama": "ollama",
    "ChatOllama": "ollama",
    "ChatMistralAI": "mistral",
    "ChatGroq": "groq",
    "ChatBedrock": "aws",
}


def detect_llm_models(
    asts: dict[str, ast.Module],
    files: list[str],
) -> list[dict[str, str]]:
    """Detect LLM model references from Python ASTs and YAML configs.

    Returns [{"model": "gpt-4o", "provider": "openai"}].
    """
    results: list[dict[str, str]] = []

    for filepath, tree in asts.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = _get_call_name(node)
            provider = MODEL_CLASSES.get(func_name)
            if not provider:
                continue
            for kw in node.keywords:
                if kw.arg in ("model", "model_name"):
                    model = _extract_string(kw.value)
                    if model and _looks_like_model_name(model):
                        results.append({"model": model, "provider": provider})

    # Also scan YAML files for CrewAI llm: directives
    for filepath in files:
        if not filepath.endswith((".yaml", ".yml")):
            continue
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith("llm:"):
                        value = stripped.split(":", 1)[1].strip().strip("\"'")
                        if "/" in value:
                            provider, model = value.split("/", 1)
                        else:
                            model = value
                            provider = _infer_provider(model)
                        if _looks_like_model_name(model):
                            results.append({"model": model, "provider": provider})
        except (IOError, UnicodeDecodeError):
            continue

    # Deduplicate
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, str]] = []
    for r in results:
        key = (r["model"], r["provider"])
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    return deduped


# ---------------------------------------------------------------------------
# Env Var Name Detection
# ---------------------------------------------------------------------------

UNIVERSAL_ENV_VARS = {
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
    "LANGCHAIN_API_KEY", "LANGSMITH_API_KEY",
}

SPECIFIC_ENV_VARS_PREFIXES: dict[str, str] = {
    "PINECONE_": "vector_store",
    "WEAVIATE_": "vector_store",
    "CHROMA_": "vector_store",
    "QDRANT_": "vector_store",
    "SLACK_": "messaging",
    "DISCORD_": "messaging",
    "TWILIO_": "messaging",
    "GMAIL_": "email",
    "SENDGRID_": "email",
    "STRIPE_": "financial",
    "PLAID_": "financial",
    "POSTGRES_": "database",
    "DATABASE_URL": "database",
    "MONGODB_": "database",
    "REDIS_": "database",
    "SUPABASE_": "database",
    "AWS_": "cloud",
    "GCP_": "cloud",
}


def detect_env_var_names(
    asts: dict[str, ast.Module],
    files: list[str],
) -> list[dict[str, str]]:
    """Detect env var names used in the project.

    Returns [{"name": "PINECONE_API_KEY", "specificity": "specific", "category": "vector_store"}].
    Never captures values — only names.
    """
    names: dict[str, dict[str, str]] = {}

    # From Python ASTs: os.environ["KEY"], os.getenv("KEY")
    for filepath, tree in asts.items():
        for node in ast.walk(tree):
            key = _extract_env_var_access(node)
            if key:
                names[key] = _classify_env_var(key)

    # From .env.example / .env.template files (never real .env)
    for filepath in files:
        basename = os.path.basename(filepath)
        if basename in (".env.example", ".env.template", ".env.sample"):
            try:
                with open(filepath, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            key = line.split("=")[0].strip()
                            if key and key == key.upper():
                                names[key] = _classify_env_var(key)
            except (IOError, UnicodeDecodeError):
                continue

    return [{"name": k, **v} for k, v in sorted(names.items())]


# ---------------------------------------------------------------------------
# Vector Store Detection
# ---------------------------------------------------------------------------

VECTOR_STORE_IMPORTS: dict[str, str] = {
    "pinecone": "pinecone",
    "chromadb": "chroma",
    "weaviate": "weaviate",
    "qdrant_client": "qdrant",
    "faiss": "faiss",
    "pymilvus": "milvus",
    "pgvector": "pgvector",
    "lancedb": "lancedb",
    "langchain_community.vectorstores": "langchain_vectorstore",
}


def detect_vector_stores(asts: dict[str, ast.Module]) -> list[str]:
    """Detect vector store usage from imports."""
    found: set[str] = set()
    for filepath, tree in asts.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for pattern, store_name in VECTOR_STORE_IMPORTS.items():
                    if pattern in node.module:
                        found.add(store_name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    for pattern, store_name in VECTOR_STORE_IMPORTS.items():
                        if pattern in alias.name:
                            found.add(store_name)
    return sorted(found)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _extract_string(node: ast.expr) -> str:
    """Extract a string constant from an AST node."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _looks_like_model_name(model: str) -> bool:
    """Heuristic: reject env var references, too-short names, etc."""
    if not model or len(model) < 3:
        return False
    if model.startswith("$") or model.startswith("{"):
        return False
    if model.upper() == model and "_" in model:
        return False  # Looks like an env var name
    return True


def _infer_provider(model: str) -> str:
    """Infer the LLM provider from a model name."""
    model_lower = model.lower()
    if "gpt" in model_lower or "o1" in model_lower or "o3" in model_lower:
        return "openai"
    if "claude" in model_lower:
        return "anthropic"
    if "gemini" in model_lower or "palm" in model_lower:
        return "google"
    if "llama" in model_lower or "mixtral" in model_lower:
        return "meta"
    if "mistral" in model_lower:
        return "mistral"
    return "unknown"


def _extract_env_var_access(node: ast.expr) -> str:
    """Extract env var name from os.environ["KEY"] or os.getenv("KEY") patterns."""
    # os.environ["KEY"] or os.environ.get("KEY")
    if isinstance(node, ast.Subscript):
        if (isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "os"
                and node.value.attr == "environ"):
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                return node.slice.value

    # os.getenv("KEY") or os.environ.get("KEY")
    if isinstance(node, ast.Call):
        func = node.func
        # os.getenv("KEY")
        if (isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
                and func.attr == "getenv"):
            if node.args and isinstance(node.args[0], ast.Constant):
                val = node.args[0].value
                if isinstance(val, str):
                    return val
        # os.environ.get("KEY")
        if (isinstance(func, ast.Attribute)
                and func.attr == "get"
                and isinstance(func.value, ast.Attribute)
                and isinstance(func.value.value, ast.Name)
                and func.value.value.id == "os"
                and func.value.attr == "environ"):
            if node.args and isinstance(node.args[0], ast.Constant):
                val = node.args[0].value
                if isinstance(val, str):
                    return val

    return ""


def _classify_env_var(key: str) -> dict[str, str]:
    """Classify an env var by specificity and category."""
    key_upper = key.upper()
    if key_upper in UNIVERSAL_ENV_VARS:
        return {"specificity": "universal", "category": "llm_api"}
    for prefix, category in SPECIFIC_ENV_VARS_PREFIXES.items():
        if key_upper.startswith(prefix) or key_upper == prefix.rstrip("_"):
            return {"specificity": "specific", "category": category}
    return {"specificity": "unknown", "category": "unknown"}
