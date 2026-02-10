"""Classification database for learning-related capabilities.

Maps library imports and function calls to learning types
for detection by rules/learning_risk.py and related modules.
"""

# --- Memory Stores ---
# Each maps import name -> store type and base learning level

MEMORY_STORES: dict[str, dict] = {
    "chromadb":                         {"type": "vector_memory",       "learning_level": "context_level"},
    "pinecone":                         {"type": "vector_memory",       "learning_level": "context_level"},
    "weaviate":                         {"type": "vector_memory",       "learning_level": "context_level"},
    "qdrant_client":                    {"type": "vector_memory",       "learning_level": "context_level"},
    "pgvector":                         {"type": "vector_memory",       "learning_level": "context_level"},
    "langchain.memory":                 {"type": "conversation_memory", "learning_level": "context_level"},
    "langchain.vectorstores":           {"type": "vector_memory",       "learning_level": "context_level"},
    "langchain_community.vectorstores": {"type": "vector_memory",       "learning_level": "context_level"},
    "mem0":                             {"type": "agent_memory",        "learning_level": "context_level"},
    "llama_index.storage":              {"type": "index_memory",        "learning_level": "context_level"},
    "llama_index.vector_stores":        {"type": "vector_memory",       "learning_level": "context_level"},
    "redis":                            {"type": "kv_memory",           "learning_level": "context_level"},
}


# --- Read/Write Operations ---
# Method names that indicate reading from or writing to a store.

CONTEXT_WRITE_METHODS: set[str] = {
    "add_documents",
    "add_texts",
    "add",
    "upsert",
    "insert",
    "persist",
    "update",
    "put",
    "set",
    "save_context",
    "add_message",
    "add_ai_message",
    "add_user_message",
}

CONTEXT_READ_METHODS: set[str] = {
    "similarity_search",
    "retrieve",
    "as_retriever",
    "query",
    "get_relevant_documents",
    "search",
    "get",
    "load_memory_variables",
    "invoke",
}


# --- Distillation Patterns ---
# Imports + method calls that suggest trace -> knowledge pipelines

DISTILLATION_SIGNALS: dict[str, list[str]] = {
    "langsmith":    ["create_dataset", "create_example", "create_examples"],
    "mlflow":       ["log_artifact", "log_model"],
    "wandb":        ["log", "save"],
}


# --- Trajectory RL / Fine-Tuning ---
# Imports that indicate model weight updates from deployment data

TRAJECTORY_RL_IMPORTS: dict[str, str] = {
    "openai.fine_tuning":    "OpenAI fine-tuning API",
    "openai":                None,  # only flag if .fine_tuning. is called
    "trl.PPOTrainer":        "PPO reinforcement learning",
    "trl.DPOTrainer":        "DPO preference optimization",
    "trl":                   None,  # only flag if PPOTrainer/DPOTrainer used
    "transformers.Trainer":  None,  # only flag if data source looks like production traces
}


# --- Telemetry Providers ---
# Maps import name -> provider info and known env vars

TELEMETRY_PROVIDERS: dict[str, dict] = {
    "langsmith":   {
        "provider": "LangChain/LangSmith",
        "env_keys": ["LANGCHAIN_TRACING_V2", "LANGSMITH_API_KEY", "LANGCHAIN_API_KEY"],
        "parent_company": "langchain",
    },
    "langfuse":    {
        "provider": "Langfuse",
        "env_keys": ["LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_HOST"],
        "parent_company": "langfuse",
    },
    "arize":       {
        "provider": "Arize AI",
        "env_keys": ["ARIZE_SPACE_KEY", "ARIZE_API_KEY"],
        "parent_company": "arize",
    },
    "galileo":     {
        "provider": "Galileo",
        "env_keys": ["GALILEO_API_KEY"],
        "parent_company": "galileo",
    },
    "braintrust":  {
        "provider": "Braintrust",
        "env_keys": ["BRAINTRUST_API_KEY"],
        "parent_company": "braintrust",
    },
    "wandb":       {
        "provider": "Weights & Biases",
        "env_keys": ["WANDB_API_KEY", "WANDB_PROJECT"],
        "parent_company": "wandb",
    },
    "mlflow":      {
        "provider": "MLflow",
        "env_keys": ["MLFLOW_TRACKING_URI", "MLFLOW_EXPERIMENT_NAME"],
        "parent_company": "mlflow",
    },
    "datadog":     {
        "provider": "Datadog",
        "env_keys": ["DD_API_KEY", "DD_LLMOBS_ENABLED", "DD_LLMOBS_ML_APP"],
        "parent_company": "datadog",
    },
    "opentelemetry": {
        "provider": "OpenTelemetry (self-hosted or vendor)",
        "env_keys": ["OTEL_EXPORTER_OTLP_ENDPOINT"],
        "parent_company": "otel",
    },
}


# --- Model Providers ---

MODEL_PROVIDERS: dict[str, str] = {
    "openai":                "OpenAI",
    "anthropic":             "Anthropic",
    "google.generativeai":   "Google",
    "google.cloud.aiplatform": "Google",
    "cohere":                "Cohere",
    "mistralai":             "Mistral",
    "together":              "Together AI",
    "groq":                  "Groq",
    "fireworks":             "Fireworks AI",
}


# --- Eval Frameworks ---

EVAL_FRAMEWORKS: dict[str, dict] = {
    "openai.evals":     {"provider": "OpenAI",      "parent_company": "openai"},
    "ragas":            {"provider": "RAGAS",        "parent_company": "independent"},
    "deepeval":         {"provider": "DeepEval",     "parent_company": "independent"},
    "promptfoo":        {"provider": "Promptfoo",    "parent_company": "independent"},
    "langsmith":        {"provider": "LangSmith",    "parent_company": "langchain"},
    "langchain.evaluation": {"provider": "LangChain","parent_company": "langchain"},
    "trulens":          {"provider": "TruLens",      "parent_company": "independent"},
}


# --- Eval Provider Conflict Pairs ---
# (model_parent, eval_parent) pairs that constitute a conflict

EVAL_CONFLICTS: set[tuple[str, str]] = {
    ("openai", "openai"),
    ("anthropic", "anthropic"),
    ("google", "google"),
}


# --- Telemetry Provider Conflict Pairs ---
# (telemetry_parent, model_parent) -> description

PROVIDER_CONFLICTS: dict[tuple[str, str], str] = {
    ("langchain", "openai"): "LangSmith (LangChain) receives full execution traces including OpenAI API calls",
    ("langchain", "anthropic"): "LangSmith (LangChain) receives full execution traces including Anthropic API calls",
    ("openai", "openai"): "OpenAI receives both model API calls and evaluation/trace data",
    ("anthropic", "anthropic"): "Anthropic receives both model API calls and evaluation/trace data",
    ("google", "google"): "Google receives both model API calls and evaluation/trace data",
}


# --- Scoping Parameters ---
# Parameter names that indicate memory scoping

SCOPING_PARAMS: set[str] = {
    "ttl", "expire_after", "max_age",
    "max_documents", "collection_size",
    "namespace", "collection_name",
}

# --- Provenance Parameters ---
# Parameter names that indicate provenance tracking on writes

PROVENANCE_PARAMS: set[str] = {
    "metadata", "source", "author", "agent_id", "timestamp",
}

# --- Identity Parameters ---
# Parameter names that indicate agent identity

IDENTITY_PARAMS: set[str] = {
    "agent_id", "name", "agent_name", "id",
}

# --- Human Credential Patterns ---
# Env var name patterns suggesting human (not service) credentials

HUMAN_CREDENTIAL_PATTERNS: list[str] = [
    "USER_", "PERSONAL_", "MY_",
]

# --- API Key Env Var Patterns ---
# Env var patterns that are likely API keys

API_KEY_PATTERNS: list[str] = [
    "API_KEY", "SECRET_KEY", "ACCESS_TOKEN", "AUTH_TOKEN",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
    "COHERE_API_KEY", "MISTRAL_API_KEY",
]

# --- Abstraction Libraries ---
# Libraries that provide model provider abstraction

ABSTRACTION_LIBRARIES: set[str] = {
    "langchain", "litellm", "haystack", "llama_index",
}

# --- Proprietary Agent Formats ---
# Import patterns indicating non-portable agent configs

PROPRIETARY_AGENT_IMPORTS: dict[str, str] = {
    "openai.beta.assistants": "OpenAI Assistants API",
}
