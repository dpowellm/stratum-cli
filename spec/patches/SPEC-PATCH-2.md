# STRATUM CLI — Self-Learning & Governance Architecture Patch

## WHY THIS PATCH EXISTS

The existing scanner answers: "What can your agent do, and is it guarded?" That covers 2024-era agents — tool-calling wrappers with no memory. It doesn't cover 2026-era agents, which learn.

An agent with a Chroma vector store that writes its own successful responses back into retrieval is a fundamentally different risk object than a stateless tool-caller. It drifts. Its behavior on day 90 is not the behavior you deployed on day 1. The agent you tested is not the agent that's running.

No other scanner detects this. Not Snyk, not Wiz, not mcp-scan. They check dependencies, permissions, and known CVEs. None of them ask: "Is this agent learning from itself? Is anyone watching what it learns? Can you undo what it learned?"

This patch adds six detection capabilities that are entirely novel in the market:

1. **Learning loop detection** — does the agent read from and write to the same store?
2. **Context integrity analysis** — can anyone verify what it learned, or roll it back?
3. **Telemetry destination mapping** — where do execution traces go, and who owns them?
4. **Evaluation conflict detection** — is the model provider grading its own homework?
5. **Agent identity analysis** — can you tell which agent did what?
6. **Portability risk signals** — can you leave your current vendor?

All six use the same static analysis approach as the existing scanner: AST parsing, import resolution, config file inspection. No runtime. No LLM. No framework-specific logic. If a file has `import chromadb` and calls both `collection.add()` and `collection.query()`, we flag the learning loop — regardless of whether it's LangChain, CrewAI, or raw Python.

---

## HONEST ASSESSMENT: WHAT SHIPS WHEN

This patch defines six modules. Not all should ship simultaneously. Here's the phasing based on signal-to-noise ratio for the actual user (indie dev building agents on GitHub):

**Phase 1 — Ship with v0.1 (genuinely novel, high signal):**
- `rules/learning_risk.py` — The headline feature. No competitor does this.
- `rules/telemetry_destination.py` — "Your traces go to OpenAI" is a "wait, what?" moment.
- `rules/agent_identity.py` — Shared credentials is a real bug, not a governance concern.

**Phase 2 — Ship in v0.2 (real value, needs tuning):**
- `rules/context_integrity.py` — Useful but hard to avoid false positives via static analysis.
- `rules/eval_integrity.py` — Novel but niche; most indie devs don't have evals at all.

**Phase 3 — Ship in v0.3 (enterprise-oriented):**
- `rules/portability_risk.py` — Enterprises care about lock-in. Indie devs don't.

The spec below defines all six completely. The implementer should ship Phase 1 first.

---

## ARCHITECTURAL PRINCIPLE: LEARNING TYPE CLASSIFICATION

Agents learn at three levels. Each level is harder to reverse and harder to govern. The scanner classifies detected learning into one of three types and escalates severity accordingly.

### Level 1: Context Accumulation (reversible in principle)

Agent adds entries to a vector store, conversation memory, or retrieval index. Future behavior is shaped by what the store returns. This is the most common pattern — every RAG agent with a write path does this.

**Reversibility:** High. Individual entries can be identified and deleted. The store can be snapshot and restored. But only if provenance metadata exists (who wrote what, when, why).

**Detection:** Vector store imports (chromadb, pinecone, weaviate, qdrant_client, pgvector) + both read calls (similarity_search, query, retrieve) and write calls (add_documents, add_texts, upsert) in the same agent scope.

**Base severity:** MEDIUM. Escalates to HIGH if no provenance or rollback.

### Level 2: Experience Distillation (partially reversible)

Agent traces are curated, summarized, or abstracted into strategies, playbooks, or synthetic examples that are fed back into prompts or retrieval. The raw trace → distilled knowledge → re-injection chain means provenance is lossy. You can see the distilled output but not always trace it back to the specific experiences that produced it.

**Reversibility:** Low. Distilled artifacts can be deleted, but determining which distilled entries are tainted requires reconstructing the derivation chain — often impossible.

**Detection:** Trace logging libraries (langsmith, langfuse, mlflow) + dataset/example creation APIs + re-injection into prompts or retrieval. This is harder to detect statically and will have higher false-negative rates.

**Base severity:** HIGH.

### Level 3: Trajectory RL / Fine-Tuning (irreversible)

Agent deployment data is used to update model weights — via fine-tuning APIs, RLHF/RLAIF pipelines, reward model training, or PPO/DPO on production traces. Learned behaviors are baked into the model and cannot be selectively removed without retraining.

**Reversibility:** None. You cannot "unlearn" a fine-tuned behavior. You can only retrain from a clean checkpoint, which requires retaining the original training data and knowing which data to exclude.

**Detection:** Fine-tuning API calls (openai.fine_tuning.jobs.create), RL training imports (trl.PPOTrainer, trl.DPOTrainer), HuggingFace Trainer with data paths pointing to production trace storage.

**Base severity:** CRITICAL.

---

## MODULE 1: `rules/learning_risk.py`

### Purpose

Detect static signals that an agent is configured for self-learning or memory accumulation, classify the learning type, and flag governance gaps.

### Detection logic

**Step 1: Identify memory stores.**

During AST scanning (extend `parsers/capabilities.py`), detect imports from the memory store knowledge base. For each detected import, record:
- Which store (chromadb, pinecone, etc.)
- The variable it's assigned to (via `var_origin` map, same as existing capability detection)
- The file and scope

**Step 2: Identify read and write operations.**

For each detected memory store variable, check if the file contains:
- Write operations: `add_documents`, `add_texts`, `upsert`, `insert`, `persist`, `add`, `update`
- Read operations: `similarity_search`, `retrieve`, `as_retriever`, `query`, `get_relevant_documents`, `search`

A function (or file) that contains both read and write operations on the same store is a learning loop.

**Step 3: Classify learning type.**

Check the import set against the three-level taxonomy:
- If `openai.fine_tuning` or `trl.PPOTrainer` or `trl.DPOTrainer` → `trajectory_rl`
- If `langsmith.Client` + `.create_dataset` or `.create_example` → `experience_distillation`
- If vector store + read/write pattern → `context_level`

Higher levels take precedence: if both context_level and trajectory_rl are detected, classify as trajectory_rl.

**Step 4: Check for scoping.**

For `UNSCOPED_MEMORY_ACCUMULATION`, check that the memory store initialization includes:
- No TTL parameter (no `ttl=`, no `expire_after=`, no `max_age=`)
- No size limit (no `max_documents=`, no `collection_size=`, no `n_results` cap on writes)
- No namespace scoping (no `namespace=`, no `collection_name` that includes agent-specific prefix)

This will have false negatives — some stores use different parameter names. That's acceptable. The goal is to catch the obvious cases where a developer created `chromadb.Client().get_or_create_collection("memory")` with zero configuration.

**Step 5: Detect shared context.**

If multiple agent definitions or function scopes reference the same collection name / store identifier, flag `SHARED_CONTEXT_MULTI_AGENT`. Detection heuristic: same string literal passed to collection creation/access in different functions or classes. This is inherently approximate via static analysis.

### Findings

```
LEARNING-001  LEARNING_LOOP_DETECTED
Severity:     MEDIUM (context_level) | HIGH (experience_distillation) | CRITICAL (trajectory_rl)
Confidence:   CONFIRMED (import resolved + read/write calls on same store variable)
              PROBABLE (import resolved + read/write calls but store variable not traced)
Category:     OPERATIONAL
OWASP:        ASI10 (Rogue Agents) — behavioral drift from accumulated context

Title:        "Self-referential learning loop detected"
Description:  "Agent reads from and writes to {store_name}. Over time, the agent's
              behavior will drift from what you deployed. Learning type: {type}.
              Reversibility: {high|low|none}."
Remediation:  Varies by type:
              context_level: "Add provenance metadata to writes (timestamp, source, agent_id).
                             Add TTL or max-size to prevent unbounded accumulation.
                             Snapshot the store before each deployment."
              experience_distillation: "Ensure trace→distillation pipeline has audit trail.
                                       Version distilled artifacts. Tag with source trace IDs."
              trajectory_rl: "Fine-tuning from production data requires explicit governance.
                             Document: what data, what filtering, what evaluation, what rollback.
                             Consider: is the fine-tuned model versioned? Can you revert?"


LEARNING-002  UNSCOPED_MEMORY_ACCUMULATION
Severity:     HIGH
Confidence:   CONFIRMED (memory store import + initialization with no TTL/size/scope parameters)
Category:     BUSINESS
OWASP:        ASI10 (Rogue Agents)

Title:        "Unbounded agent memory with no expiry or limits"
Description:  "Memory store {store_name} has no TTL, no size limit, and no access scoping.
              The agent will accumulate context indefinitely. This is both a drift risk
              (old context shapes new behavior unpredictably) and an attack surface
              (anyone who can write to the store can shape the agent's future behavior)."
Remediation:  "Add TTL: collection = client.get_or_create_collection('memory', metadata={'ttl': 86400})
              Add size limit: configure max_documents or implement periodic cleanup.
              Add namespace: scope collections by agent_id, tenant, or deployment."


LEARNING-003  SHARED_CONTEXT_MULTI_AGENT
Severity:     HIGH
Confidence:   PROBABLE (same collection name string in different scopes — could be coincidence)
Category:     COMPOUNDING
OWASP:        ASI07 (Insecure Inter-Agent Communication)

Title:        "Multiple agents share the same memory store"
Description:  "Agents in {file_a} and {file_b} reference collection '{collection_name}'.
              If one agent writes poisoned or incorrect context, all agents that read
              from this store inherit the corruption simultaneously. This is the agent
              equivalent of a shared mutable global variable."
Remediation:  "Use agent-specific namespaces: collection_name=f'memory_{agent_id}'.
              If shared context is intentional, add write validation and provenance
              tracking so you can attribute and rollback per-agent."


LEARNING-004  TRAJECTORY_RL_FROM_PRODUCTION
Severity:     CRITICAL
Confidence:   CONFIRMED (fine-tuning API import + call, or RL trainer import)
Category:     SECURITY
OWASP:        ASI10 (Rogue Agents)

Title:        "Model fine-tuning from production data detected"
Description:  "Fine-tuning or RL pipeline detected ({evidence}). Model weight updates
              from production data are irreversible without full retraining.
              Learned behaviors cannot be selectively removed.
              This is the least governable form of agent learning."
Remediation:  "Document the fine-tuning pipeline: data source, filtering criteria,
              evaluation protocol, model versioning, rollback procedure.
              Version every fine-tuned model checkpoint.
              Never fine-tune directly on unfiltered production data."
```

---

## MODULE 2: `rules/context_integrity.py`

### Purpose

Detect missing integrity controls on agent context and memory. These findings only fire when a learning pattern is detected — they're modifiers on LEARNING-001/002, not standalone findings.

### Detection logic

When a memory store is detected (Module 1, Step 1), additionally check:

**Provenance:** Do write calls include metadata parameters? Look for `metadata=`, `source=`, `author=`, `agent_id=`, `timestamp=` in the arguments to write operations. If none found → `NO_CONTEXT_PROVENANCE`.

**Rollback:** Does the codebase contain any snapshot/backup/versioning pattern for the memory store? Look for: `.snapshot()`, `.backup()`, `version=` parameter, git-based versioning of store files, any function named `*backup*` or `*snapshot*` that references the store. If none found → `NO_CONTEXT_ROLLBACK`.

**Write scoping:** For shared stores (LEARNING-003), do write calls include authentication, agent-specific namespace, or permission checks? Look for: `namespace=`, `agent_id=` in write calls, auth token parameters, permission checks before writes. If none found → `UNPROTECTED_SHARED_CONTEXT_WRITES`.

### Findings

```
CONTEXT-001  NO_CONTEXT_PROVENANCE
Severity:    MEDIUM
Confidence:  PROBABLE (absence of metadata parameters — could be handled elsewhere)
Category:    COMPLIANCE
OWASP:       ASI10 (Rogue Agents)

Title:       "Memory writes have no provenance tracking"
Description: "Writes to {store_name} include no attribution metadata (source, timestamp,
             agent_id). When the agent learns something wrong, you cannot determine
             which input caused it or when it entered the store."
Remediation: "Add metadata to writes:
             collection.add(documents=[doc], metadatas=[{
                 'source': 'tool_result',
                 'agent_id': AGENT_ID,
                 'timestamp': datetime.utcnow().isoformat(),
                 'session_id': session_id,
             }])"


CONTEXT-002  NO_CONTEXT_ROLLBACK
Severity:    MEDIUM
Confidence:  PROBABLE
Category:    OPERATIONAL
OWASP:       ASI10 (Rogue Agents)

Title:       "No versioning or rollback on agent memory"
Description: "No snapshot, backup, or versioning pattern detected for {store_name}.
             If the agent accumulates bad context, you have no mechanism to revert
             to a known-good state. The only option is wiping the entire store."
Remediation: "Snapshot before deployments:
             # Before deploying new agent version
             shutil.copytree(chroma_persist_dir, f'{chroma_persist_dir}_backup_{date}')
             
             Or use a vector store with built-in versioning (Pinecone collections,
             Weaviate backups, pgvector with row-level timestamps for selective rollback)."


CONTEXT-003  UNPROTECTED_SHARED_CONTEXT_WRITES
Severity:    HIGH
Confidence:  PROBABLE (only fires when LEARNING-003 also fires)
Category:    SECURITY
OWASP:       ASI07 (Insecure Inter-Agent Communication)

Title:       "Unscoped writes to shared agent memory"
Description: "Any agent can write to collection '{collection_name}' with no
             authentication, namespace scoping, or permission check. A compromised
             or misbehaving agent can poison the shared context for all consumers."
Remediation: "Scope writes by agent:
             collection.add(documents=[doc], ids=[f'{agent_id}_{doc_id}'],
                           metadatas=[{'author_agent': agent_id}])
             
             Validate on read:
             results = collection.query(query_texts=[q], where={'author_agent': {'$in': trusted_agents}})"
```

---

## MODULE 3: `rules/telemetry_destination.py`

### Purpose

Detect where agent execution traces, logs, and telemetry are sent. This is the "who owns the learning loop" question — the most consequential data governance issue for any organization deploying agents.

This is a finding that no other scanner produces. It's also the finding that makes an enterprise security team say "wait, show me that again."

### Detection logic

**Step 1: Detect telemetry SDK imports.**

Scan for imports from known telemetry/observability providers. Use the knowledge base in `knowledge/learning_patterns.py` → `TELEMETRY_PROVIDERS`.

**Step 2: Detect telemetry environment variables.**

Scan `.env` files and `os.environ.get()` / `os.getenv()` calls for known telemetry env vars (LANGCHAIN_TRACING_V2, LANGSMITH_API_KEY, ARIZE_SPACE_KEY, etc.).

**Step 3: Detect model provider.**

Scan for imports from known model providers. Use `MODEL_PROVIDERS` knowledge base.

**Step 4: Cross-reference.**

If telemetry provider and model provider map to the same parent company (e.g., LangSmith traces + OpenAI model, or both are LangChain ecosystem), flag `TRACE_DATA_TO_MODEL_PROVIDER` at elevated severity.

### Provider mapping for conflict detection

```python
# These pairs trigger TRACE_DATA_TO_MODEL_PROVIDER
PROVIDER_CONFLICTS = {
    # LangSmith is LangChain Inc; when used with any model, it's the orchestration
    # layer seeing everything. Not a direct model provider conflict, but still a
    # data concentration concern.
    ("langsmith", "openai"): "LangSmith (LangChain) receives full execution traces including OpenAI API calls",
    ("langsmith", "anthropic"): "LangSmith (LangChain) receives full execution traces including Anthropic API calls",
    
    # Direct model provider conflicts
    ("openai", "openai"): "OpenAI receives both model API calls and evaluation/trace data",
    ("anthropic", "anthropic"): "Anthropic receives both model API calls and evaluation/trace data",
    ("google", "google"): "Google receives both model API calls and evaluation/trace data",
}
```

### Findings

```
TELEMETRY-001  TRACE_DATA_EXTERNAL_DESTINATION
Severity:      MEDIUM
Confidence:    CONFIRMED (telemetry SDK import + env config)
Category:      COMPLIANCE
OWASP:         ASI04 (Supply Chain & Environment Risks)

Title:         "Agent traces sent to external provider"
Description:   "Execution traces are sent to {provider}. Trace data includes tool
               calls, model inputs/outputs, and error details. This data may contain
               business logic, customer data, and agent behavior patterns.
               Data ownership and usage rights should be reviewed."
Remediation:   "Review {provider}'s data retention and usage policies.
               Consider self-hosted alternatives: Langfuse (self-host), MLflow (self-host),
               OpenTelemetry with your own collector.
               At minimum: understand what data is sent and who can access it."


TELEMETRY-002  TRACE_DATA_TO_MODEL_PROVIDER
Severity:      HIGH
Confidence:    CONFIRMED
Category:      COMPLIANCE
OWASP:         ASI04 (Supply Chain & Environment Risks)

Title:         "Trace data flows back to model/platform provider"
Description:   "{conflict_description}. This creates informational asymmetry:
               the provider observes your agent's business logic, tool usage,
               failure modes, and customer interaction patterns. This data may
               inform the provider's own product development."
Remediation:   "Use a provider-independent observability stack:
               - Langfuse (open source, self-hostable)
               - OpenTelemetry + your own collector
               - MLflow (self-hostable)
               Separate model provider from observability provider."


TELEMETRY-003  NO_TELEMETRY_CONFIGURED
Severity:      LOW
Confidence:    PROBABLE (absence evidence — telemetry could be configured elsewhere)
Category:      OPERATIONAL
OWASP:         ASI05 (Insufficient Sandboxing / Control)

Title:         "No observability or tracing detected"
Description:   "No telemetry SDK or tracing configuration found. Agent behavior
               cannot be audited, monitored for drift, or debugged in production."
Remediation:   "Add observability. Options:
               - Langfuse (open source): pip install langfuse
               - LangSmith: set LANGCHAIN_TRACING_V2=true (review data policies)
               - OpenTelemetry: vendor-neutral, self-hostable"
```

---

## MODULE 4: `rules/eval_integrity.py`

### Purpose

Detect evaluation conflict of interest — when the same provider or ecosystem powers both the agent execution and the evaluation layer.

This is a subtle but important finding. When OpenAI provides both the model and the evals, there's a structural incentive to surface favorable results. The developer may not realize they're grading homework with the teacher's answer key.

### Detection logic

**Step 1: Identify model provider.** From imports: `openai` → OpenAI, `anthropic` → Anthropic, `google.generativeai` → Google, etc.

**Step 2: Identify eval framework.** From imports:
- `openai.evals` or `openai` + eval-related function names → OpenAI evals
- `langsmith` + `evaluate` or `RunEvalConfig` → LangSmith evals
- `ragas` → RAGAS (independent)
- `deepeval` → DeepEval (independent)
- `promptfoo` → Promptfoo (independent)

**Step 3: Match.** If model provider and eval provider belong to the same company/ecosystem, flag it.

### Findings

```
EVAL-001  EVAL_PROVIDER_CONFLICT
Severity:  MEDIUM
Confidence: CONFIRMED (both imports resolved)
Category:  BUSINESS
OWASP:     ASI09 (Human-Agent Trust Exploitation)

Title:     "Model provider and evaluation share the same ecosystem"
Description: "Agent uses {model_provider} for inference and {eval_provider} for
             evaluation. When the model provider also operates the evaluation
             layer, metrics may implicitly favor the provider's own models.
             This is a structural conflict, not necessarily intentional bias."
Remediation: "Consider adding an independent evaluation framework:
             - RAGAS (open source, model-agnostic)
             - DeepEval (open source)
             - Promptfoo (open source, multi-provider)
             Use the independent framework for critical evaluations.
             The provider's own evals are fine for development iteration."


EVAL-002  NO_EVAL_FRAMEWORK
Severity:  MEDIUM
Confidence: PROBABLE
Category:  OPERATIONAL
OWASP:     ASI05 (Insufficient Sandboxing / Control)

Title:     "No evaluation framework detected"
Description: "No evaluation or testing framework found for agent outputs.
             Agent output quality is unmonitored — you won't know when
             it degrades until users complain."
Remediation: "Add basic evals. Start simple:
             - Promptfoo: YAML-based, no code required
             - DeepEval: pytest-like, Python-native
             - RAGAS: specialized for RAG pipelines
             Even 5 test cases that run on every deploy catch regressions."
```

---

## MODULE 5: `rules/agent_identity.py`

### Purpose

Detect agent identity and credential hygiene. Multiple agents sharing the same API key is a real security bug, not a governance abstraction — it makes audit impossible and revocation dangerous.

### Detection logic

**Step 1: Identify agent definitions.**

Heuristic: a class or function that instantiates an LLM client (OpenAI, Anthropic, etc.) and uses tool-calling or agent frameworks. Each such instantiation is an "agent" for identity purposes.

**Step 2: Check credential sharing.**

If multiple agent definitions reference the same environment variable for API keys (e.g., both use `os.getenv("OPENAI_API_KEY")` or both use the same hardcoded key), flag `SHARED_AGENT_CREDENTIALS`.

Detection: collect all `os.getenv()` / `os.environ[]` / `os.environ.get()` calls for known API key variable names. If the same variable name appears in multiple agent scopes, flag it.

**Step 3: Check for unique identity.**

Does each agent definition include a unique identifier? Look for: `agent_id=`, `name=`, `agent_name=`, `id=` parameters in agent constructor calls, or class-level `name` / `agent_id` attributes. If none → `NO_AGENT_IDENTITY`.

**Step 4: Check credential type.**

Heuristic for human vs. service credentials: env var names containing `USER_`, `PERSONAL_`, or OAuth-style tokens with user scopes suggest human credentials on an agent. This is low-confidence (HEURISTIC) and capped at MEDIUM.

### Findings

```
IDENTITY-001  SHARED_AGENT_CREDENTIALS
Severity:     HIGH
Confidence:   CONFIRMED (same env var string in multiple agent scopes)
Category:     SECURITY
OWASP:        ASI03 (Identity & Privilege Abuse)

Title:        "Multiple agents share the same API credentials"
Description:  "Agents in {locations} all use {env_var}. Shared credentials make
              it impossible to: attribute API calls to specific agents, audit
              per-agent behavior, revoke one agent's access without disrupting
              others, or enforce per-agent rate limits."
Remediation:  "Use per-agent API keys:
              agent_a_key = os.getenv('OPENAI_API_KEY_AGENT_A')
              agent_b_key = os.getenv('OPENAI_API_KEY_AGENT_B')
              
              If using a single org, create per-agent project keys in your
              provider's dashboard."


IDENTITY-002  NO_AGENT_IDENTITY
Severity:     MEDIUM
Confidence:   PROBABLE (absence of identity parameters — could be set at runtime)
Category:     COMPLIANCE
OWASP:        ASI03 (Identity & Privilege Abuse)

Title:        "Agent has no unique identifier"
Description:  "No agent_id, name, or unique identifier found in agent configuration.
              Audit trails cannot distinguish between agents. As regulatory frameworks
              mature, per-agent attribution will be required."
Remediation:  "Add a unique identifier to each agent:
              agent = Agent(name='customer_support_v2', agent_id=str(uuid.uuid4())[:8])
              
              Log the agent_id with every action for audit trails."


IDENTITY-003  HUMAN_CREDENTIALS_ON_AGENT
Severity:     HIGH
Confidence:   HEURISTIC (env var naming convention — could be misidentified)
              Capped at MEDIUM per spec: HEURISTIC confidence = max MEDIUM
Category:     SECURITY
OWASP:        ASI03 (Identity & Privilege Abuse)

Title:        "Agent may be using human user credentials"
Description:  "Credential variable {env_var} suggests human user credentials
              rather than a service identity. The agent inherits the human's
              full permission scope — actions cannot be distinguished from
              the human's own actions in audit logs."
Remediation:  "Create a dedicated service account / API key for the agent
              with least-privilege permissions. Don't reuse personal credentials."
```

Note: IDENTITY-003 is HEURISTIC confidence and therefore capped at MEDIUM severity per the spec's hard acceptance criterion. This is correct — env var naming is not a reliable signal.

---

## MODULE 6: `rules/portability_risk.py`

### Purpose

Detect vendor lock-in signals. This is a Phase 3 feature — useful for enterprises evaluating migration risk, not for indie devs.

### Detection logic

**Step 1: Detect direct SDK coupling.**

If all model calls use a single provider's SDK directly (e.g., only `import openai`, never through an abstraction like LangChain, LiteLLM, or a custom wrapper), flag `NO_ABSTRACTION_LAYER`.

Detection: collect all model provider imports. If exactly one provider and no abstraction library (langchain, litellm, haystack, llama_index), flag it.

**Step 2: Detect single-provider guardrails.**

If all detected guardrails come from a single vendor (e.g., only OpenAI moderation, only Anthropic constitutional AI), flag `SINGLE_PROVIDER_GUARDRAILS`.

**Step 3: Detect proprietary agent configs.**

OpenAI Assistants API configuration (via `openai.beta.assistants`) has no open-standard equivalent. If the sole agent definition is in this format, flag `NON_PORTABLE_AGENT_CONFIG`.

### Findings

```
PORTABILITY-001  NO_ABSTRACTION_LAYER
Severity:        LOW
Confidence:      CONFIRMED
Category:        OPERATIONAL
OWASP:           (none — this is a business/operational concern, not a security risk)

Title:           "Direct SDK calls to single model provider"
Description:     "All model calls use {provider} SDK directly with no abstraction
                 layer. Switching providers requires rewriting agent code."
Remediation:     "Consider an abstraction:
                 - LiteLLM: drop-in OpenAI-compatible wrapper for 100+ providers
                 - LangChain: provider-agnostic model interface
                 - Custom wrapper: def get_completion(prompt): ... "


PORTABILITY-002  SINGLE_PROVIDER_GUARDRAILS
Severity:        MEDIUM
Confidence:      CONFIRMED
Category:        OPERATIONAL
OWASP:           ASI05 (Insufficient Sandboxing / Control)

Title:           "All safety controls depend on single provider"
Description:     "All detected guardrails use {provider}. Provider outage or
                 policy change removes all safety controls simultaneously."
Remediation:     "Add a local guardrail layer that works regardless of provider:
                 - Guardrails AI (open source, runs locally)
                 - NeMo Guardrails (NVIDIA, runs locally)
                 - Custom regex/rule-based pre-filter for obvious cases"


PORTABILITY-003  NON_PORTABLE_AGENT_CONFIG
Severity:        LOW
Confidence:      CONFIRMED
Category:        OPERATIONAL
OWASP:           (none)

Title:           "Agent config in proprietary format"
Description:     "Agent is defined via {format} with no open-standard equivalent.
                 Migration to an alternative requires significant rework."
Remediation:     "Document your agent's behavior spec independently of the provider:
                 - Tool definitions (what each tool does, inputs, outputs)
                 - System prompt (the agent's instructions)
                 - Guardrail rules (what's allowed, what's not)
                 This documentation is your portability insurance."
```

---

## KNOWLEDGE BASE: `knowledge/learning_patterns.py`

```python
"""Classification database for learning-related capabilities.

Maps library imports and function calls to learning types
for detection by rules/learning_risk.py and related modules.
"""

# --- Memory Stores ---
# Each maps import name → store type and base learning level

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
    # redis already detected as data_access — only flag for learning if
    # read/write loop pattern is also present
}


# --- Read/Write Operations ---
# Method names that indicate reading from or writing to a store.
# Used to detect self-referential learning loops.

CONTEXT_WRITE_METHODS: set[str] = {
    "add_documents",
    "add_texts",
    "add",
    "upsert",
    "insert",
    "persist",
    "update",
    "put",
    "set",           # only in combination with memory store import
    "save_context",  # LangChain memory
    "add_message",   # LangChain message history
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
    "get",           # only in combination with memory store import
    "load_memory_variables",  # LangChain memory
    "invoke",        # LangChain retriever
}


# --- Distillation Patterns ---
# Imports + method calls that suggest trace → knowledge pipelines

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
# Maps import name → provider info and known env vars

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
        "parent_company": "mlflow",  # open source, but tracking server may be vendor-hosted
    },
    "datadog":     {
        "provider": "Datadog",
        "env_keys": ["DD_API_KEY", "DD_LLMOBS_ENABLED", "DD_LLMOBS_ML_APP"],
        "parent_company": "datadog",
    },
    "opentelemetry": {
        "provider": "OpenTelemetry (self-hosted or vendor)",
        "env_keys": ["OTEL_EXPORTER_OTLP_ENDPOINT"],
        "parent_company": "otel",  # self-hosted by default
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
    ("openai", "openai"),       # OpenAI model evaluated by OpenAI evals
    ("anthropic", "anthropic"), # Anthropic model evaluated by Anthropic
    ("google", "google"),       # Google model evaluated by Google
    # Note: LangSmith + any provider is NOT flagged as a conflict.
    # LangSmith is an orchestration layer, not a model provider.
    # It's flagged separately via TELEMETRY-002 instead.
}
```

---

## MODEL EXTENSIONS

### Additions to `Capability` dataclass

```python
@dataclass
class Capability:
    # ... all existing fields unchanged ...

    # Learning-related (populated by learning_risk scanner)
    has_memory: bool = False
    memory_type: str | None = None      # "vector", "conversation", "file", "custom"
    memory_store: str = ""              # e.g. "chromadb", "pinecone"
    memory_is_shared: bool = False
    writes_to_memory: bool = False
    reads_from_memory: bool = False
```

### New dataclass: `AgentProfile` (not to be confused with the terminal "Agent Profile" display)

```python
@dataclass
class AgentProfile:
    """Metadata about an agent definition detected in the project.
    
    An "agent" is defined heuristically as any scope that instantiates
    an LLM client and uses tool-calling or agent framework patterns.
    """
    source_file: str
    scope_name: str             # function or class name
    model_provider: str = ""    # "openai", "anthropic", etc.
    has_unique_identity: bool = False
    credential_env_var: str = ""  # the API key env var this agent uses
    
    # Learning
    learning_type: str | None = None     # "context_level" | "experience_distillation" | "trajectory_rl"
    memory_stores: list[str] = field(default_factory=list)  # collection names
    
    # Telemetry
    telemetry_destinations: list[str] = field(default_factory=list)  # provider names
    
    # Eval
    eval_provider: str | None = None
```

### Additions to `ScanResult`

```python
@dataclass
class ScanResult:
    # ... all existing fields unchanged ...
    
    # Learning & Governance (NEW)
    agent_profiles: list[AgentProfile] = field(default_factory=list)
    learning_type: str | None = None    # highest detected: trajectory_rl > experience_distillation > context_level
    has_learning_loop: bool = False
    has_shared_context: bool = False
    telemetry_destinations: list[str] = field(default_factory=list)
    has_eval_conflict: bool = False
```

### Additions to `TelemetryProfile`

```python
@dataclass
class TelemetryProfile:
    # ... all existing fields unchanged ...
    
    # Learning & Governance signals (NEW)
    has_memory_store: bool = False
    memory_store_types: list[str] = field(default_factory=list)  # ["vector", "conversation"]
    has_learning_loop: bool = False
    learning_type: str | None = None
    has_context_provenance: bool = False
    has_context_rollback: bool = False
    has_shared_context: bool = False
    telemetry_destination_count: int = 0
    has_eval_framework: bool = False
    has_eval_conflict: bool = False
    agent_count: int = 0
    has_shared_credentials: bool = False
    has_agent_identity: bool = False
```

### New `RiskCategory` value

```python
class RiskCategory(str, Enum):
    SECURITY = "security"
    OPERATIONAL = "operational"
    BUSINESS = "business"
    COMPOUNDING = "compounding"   # NEW — risks that multiply across agents/systems
    COMPLIANCE = "compliance"     # NEW — regulatory and audit concerns
```

### New risk path: `LEARNING_DRIFT`

Add to the path rules as rule 11 (or next available):

```
11. Learning drift: memory accumulation + no integrity controls → shared context + no human review
    Trigger: LEARNING-001 + (CONTEXT-001 or CONTEXT-002) + LEARNING-003 + no HITL
    Severity: HIGH (context_level) or CRITICAL (experience_distillation / trajectory_rl)
    Description: "Agent learns from deployment with no provenance, no rollback, and shared
                 context across multiple agents. Drift in one agent propagates to all."
```

---

## RISK SCORE EXTENSIONS

Add to the bonus scoring in `scanner.py`:

```python
# Learning & governance bonuses
# Learning loop with no integrity controls (no provenance + no rollback)
if has_learning_loop and not has_context_provenance and not has_context_rollback:
    score += 12

# Shared context with no write scoping
if has_shared_context and not has_scoped_writes:
    score += 15

# Trajectory RL from production data
if learning_type == "trajectory_rl":
    score += 20

# Trace data flowing to model provider
if has_trace_to_model_provider:
    score += 8

# Eval provider conflict
if has_eval_conflict:
    score += 5

# Shared agent credentials across >1 agent
if has_shared_credentials:
    score += 10

# No agent identity across >1 agent
if agent_count > 1 and not all_have_identity:
    score += 8

# Cap still applies
score = min(score, 100)
```

---

## TERMINAL OUTPUT EXTENSIONS

### New section headers

When learning/governance findings exist, they appear in two new grouped sections after existing findings:

```
LEARNING & DRIFT RISK

HIGH      LEARNING-001 · ASI10  Self-referential learning loop detected
          Agent reads from and writes to 'agent_memory' (chromadb).
          Learning type: context_level. Reversibility: high.
          ▸ Unbounded context accumulation is a top-10 drift risk — OWASP ASI10

HIGH      LEARNING-002 · ASI10  Unbounded agent memory with no expiry
          Collection 'agent_memory' has no TTL, size limit, or namespace scoping.

MEDIUM    CONTEXT-001 · ASI10   Memory writes have no provenance tracking
          Writes to 'agent_memory' include no source, timestamp, or agent_id.

MEDIUM    CONTEXT-002 · ASI10   No versioning or rollback on agent memory
          No snapshot or backup pattern detected for chromadb store.

HIGH      LEARNING-003 · ASI07  Multiple agents share the same memory store
          research_agent and writer_agent both reference 'agent_memory'.

HIGH      CONTEXT-003 · ASI07   Unscoped writes to shared agent memory
          Any agent can write to 'agent_memory' with no permission check.


GOVERNANCE ARCHITECTURE

HIGH      TELEMETRY-002 · ASI04  Trace data flows to model/platform provider
          LangSmith receives full execution traces including OpenAI API calls.

MEDIUM    EVAL-001 · ASI09       Model and evaluation share same ecosystem
          OpenAI model evaluated by OpenAI evals.

HIGH      IDENTITY-001 · ASI03   Multiple agents share same API credentials
          research_agent and writer_agent both use OPENAI_API_KEY.

MEDIUM    IDENTITY-002 · ASI03   Agent has no unique identifier
          2 agents have no agent_id or name in configuration.
```

### Section ordering in `--dev` mode

```
1. RELIABILITY          (STRATUM-008, STRATUM-009, ENV-001)
2. OPERATIONAL          (STRATUM-002, STRATUM-007)
3. LEARNING & DRIFT     (LEARNING-*, CONTEXT-*)
4. GOVERNANCE           (TELEMETRY-*, EVAL-*, IDENTITY-*, PORTABILITY-*)
5. SECURITY             (STRATUM-001, STRATUM-003, STRATUM-005, STRATUM-006)
```

Learning/drift is positioned before security because it's a "wait, I didn't know my agent does that" moment — the same surprise principle from the DX patch. The developer didn't realize their agent was learning from itself. That's more immediately interesting than abstract security risks.

---

## TEST FIXTURE: `test_project/learning_agent.py`

```python
"""Multi-agent system with shared memory and learning loops.

This fixture demonstrates governance gaps that Stratum should detect:
- Self-referential learning loop (read + write to same store)
- Unbounded memory accumulation (no TTL, no limits)
- Shared context across agents (same collection)
- No provenance on writes
- No versioning / rollback
- Shared API credentials
- No unique agent identifiers
- Telemetry to external provider
- Eval provider conflict
"""

import os
import json
from datetime import datetime

import openai
import chromadb
from chromadb.config import Settings

# Both agents share credentials — no per-agent keys
client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Shared vector store — no namespace, no TTL, no size limit
chroma_client = chromadb.Client(Settings(anonymized_telemetry=False))
memory = chroma_client.get_or_create_collection("agent_memory")

# LangSmith tracing enabled via env vars
# (LANGCHAIN_TRACING_V2=true and LANGSMITH_API_KEY are expected in .env)
os.environ.get("LANGCHAIN_TRACING_V2")
os.environ.get("LANGSMITH_API_KEY")

# OpenAI evals for evaluation — same provider as the model
try:
    import openai.evals
except ImportError:
    pass


def research_agent(query: str) -> str:
    """Agent that researches a topic and stores findings in shared memory."""
    
    # Read from memory — check if we've researched this before
    existing = memory.query(query_texts=[query], n_results=3)
    
    context = ""
    if existing and existing["documents"][0]:
        context = "\n".join(existing["documents"][0])
    
    # Call OpenAI
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": f"You are a research agent. Prior knowledge:\n{context}"},
            {"role": "user", "content": query}
        ]
    )
    
    result = response.choices[0].message.content
    
    # Write back to memory — no provenance metadata, no TTL
    memory.add(
        documents=[result],
        ids=[f"research_{datetime.now().timestamp()}"],
    )
    
    return result


def writer_agent(topic: str) -> str:
    """Agent that writes content based on shared memory from research agent."""
    
    # Read from the SAME memory store as research_agent
    research = memory.query(query_texts=[topic], n_results=5)
    
    context = "\n".join(research["documents"][0]) if research["documents"][0] else ""
    
    # Same OpenAI client, same API key
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": f"Write a blog post. Research:\n{context}"},
            {"role": "user", "content": f"Write about: {topic}"}
        ]
    )
    
    result = response.choices[0].message.content
    
    # Writer also writes back to shared memory
    memory.add(
        documents=[result],
        ids=[f"writing_{datetime.now().timestamp()}"],
    )
    
    return result


def run_pipeline(query: str):
    """Run research → writing pipeline."""
    research = research_agent(query)
    article = writer_agent(query)
    
    # Log results (no structured telemetry, just print)
    print(json.dumps({
        "query": query,
        "research_length": len(research),
        "article_length": len(article),
    }))
    
    return article
```

### Expected findings from this fixture

| Finding | Severity | Trigger |
|---------|----------|---------|
| LEARNING-001 | MEDIUM | research_agent: memory.query + memory.add on same collection |
| LEARNING-001 | MEDIUM | writer_agent: same pattern |
| LEARNING-002 | HIGH | chromadb collection with no TTL/size/scope |
| LEARNING-003 | HIGH | research_agent + writer_agent both reference "agent_memory" |
| CONTEXT-001 | MEDIUM | memory.add() has no metadata param |
| CONTEXT-002 | MEDIUM | no snapshot/backup pattern in codebase |
| CONTEXT-003 | HIGH | shared collection, no namespace or auth |
| TELEMETRY-001 | MEDIUM | LANGSMITH env vars detected |
| TELEMETRY-002 | HIGH | LangSmith traces + OpenAI model |
| EVAL-001 | MEDIUM | openai model + openai.evals import |
| IDENTITY-001 | HIGH | both agents use same OPENAI_API_KEY |
| IDENTITY-002 | MEDIUM | neither agent has agent_id or name |

That's 12 new findings from a single test file, with zero false positives on the existing test fixtures (the new rules only fire when learning/telemetry/identity patterns are detected).

---

## VALIDATION (ADDITIONS 79–100)

**Learning risk:**
79. LEARNING-001 fires when same file imports chromadb AND calls both `.query()` and `.add()` on a collection variable
80. LEARNING-001 does NOT fire for a file that only reads from a vector store (no write operations)
81. LEARNING-002 fires when collection creation has no TTL, max_documents, or namespace parameters
82. LEARNING-003 fires when two different function scopes reference the same collection name string
83. LEARNING-004 fires when `openai.fine_tuning` import is resolved
84. Learning type classification: chromadb read/write → context_level, langsmith create_dataset → experience_distillation, openai.fine_tuning → trajectory_rl
85. LEARNING-001 severity escalates: MEDIUM for context_level, HIGH for experience_distillation, CRITICAL for trajectory_rl

**Context integrity:**
86. CONTEXT-001 fires only when a LEARNING-001 finding also exists (not standalone)
87. CONTEXT-002 fires only when a memory store is detected
88. CONTEXT-003 fires only when LEARNING-003 also fires (shared context exists)

**Telemetry destination:**
89. TELEMETRY-001 fires when langsmith/arize/langfuse/etc import is resolved OR known env vars are detected
90. TELEMETRY-002 fires when telemetry provider + model provider match conflict pairs
91. TELEMETRY-003 fires only when NO telemetry SDK or env var is detected at all
92. TELEMETRY-003 does NOT fire when telemetry IS detected (mutually exclusive with 001/002)

**Eval integrity:**
93. EVAL-001 fires when model provider and eval provider share parent company
94. EVAL-001 does NOT fire when eval provider is independent (ragas, deepeval, promptfoo)
95. EVAL-002 fires only when no eval framework import is detected

**Agent identity:**
96. IDENTITY-001 fires when ≥2 agent scopes reference the same API key env var
97. IDENTITY-001 does NOT fire when only one agent scope exists
98. IDENTITY-002 fires when agent scope has no name/agent_id parameter
99. IDENTITY-003 is capped at MEDIUM due to HEURISTIC confidence (spec rule)

**Integration:**
100. All existing test fixtures (tools.py, agent.py, etc.) produce zero findings from the new rules (no chromadb, no langsmith, no multi-agent patterns)
101. test_project/learning_agent.py produces ≥10 findings from new rules
102. Risk score increases when learning + no integrity controls are present
103. LEARNING & DRIFT RISK section header appears only when learning findings exist
104. GOVERNANCE ARCHITECTURE section header appears only when governance findings exist
105. `--dev` mode orders: reliability → operational → learning → governance → security

---

## PROJECT STRUCTURE (ADDITIONS)

```
stratum/
├── rules/
│   ├── paths.py              # existing — add LEARNING_DRIFT path rule
│   ├── learning_risk.py      # NEW — Phase 1
│   ├── context_integrity.py  # NEW — Phase 2
│   ├── telemetry_dest.py     # NEW — Phase 1
│   ├── eval_integrity.py     # NEW — Phase 2
│   ├── agent_identity.py     # NEW — Phase 1
│   └── portability_risk.py   # NEW — Phase 3
├── knowledge/
│   ├── db.py                 # existing
│   └── learning_patterns.py  # NEW — knowledge base for all new modules
├── research/                 # from Research Intelligence patch
│   └── ...
test_project/
├── tools.py                  # existing
├── agent.py                  # existing
└── learning_agent.py         # NEW — test fixture for this patch
```

---

## WHAT THIS DOES NOT CHANGE

- All existing scan logic — unchanged
- All existing rules (STRATUM-001 through STRATUM-010, ENV-001) — unchanged
- All existing models (additive fields only, all with defaults) — backward compatible
- Capability detection for outbound/data_access/code_exec/destructive/financial — unchanged
- MCP parsing — unchanged
- Risk score formula — extended but base behavior identical for projects with no learning patterns
- Terminal output for non-learning projects — identical
- All previous validation targets (1–78) — unchanged
- Open-core boundary — unchanged
- Telemetry profile — extended with new boolean/count fields, backward compatible

---

## IMPLEMENTATION SEQUENCE

1. **Create `knowledge/learning_patterns.py`** — Pure data, no logic. Foundation for everything else.
2. **Extend `models.py`** — Add fields to Capability, create AgentProfile, extend ScanResult and TelemetryProfile. All additive with defaults.
3. **Create `rules/learning_risk.py`** — The headline feature. Depends on knowledge base.
4. **Create `rules/telemetry_dest.py`** — Highest surprise factor for users.
5. **Create `rules/agent_identity.py`** — Real security value.
6. **Create `rules/context_integrity.py`** — Modifier findings on learning_risk.
7. **Create `rules/eval_integrity.py`** — Smallest module, simple matching.
8. **Create `rules/portability_risk.py`** — Lowest priority, can defer.
9. **Create `test_project/learning_agent.py`** — Test fixture.
10. **Extend `parsers/capabilities.py`** — Add memory store detection to AST scanner.
11. **Extend `rules/engine.py`** — Wire new rule modules into evaluation pipeline.
12. **Extend `output/terminal.py`** — Add LEARNING & DRIFT RISK and GOVERNANCE ARCHITECTURE sections.
13. **Extend `scanner.py`** — Add learning/governance bonus scoring.

Steps 1–5 are Phase 1 (ship with v0.1). Steps 6–8 are Phase 2–3. Steps 9–13 support all phases.

---

## IMPLEMENTATION COMMAND

```bash
claude --max-turns 60 "Read SPEC.md, then all PATCH files in order (TELEMETRY-PRIMITIVES, OPEN-CORE-BOUNDARY, OPEN-CORE-STRATEGY-AMENDMENT, DEVELOPER-EXPERIENCE, RESEARCH-INTELLIGENCE, SPEC-PATCH-2). Implement SPEC-PATCH-2 Phase 1 (learning_risk, telemetry_dest, agent_identity + knowledge base + models + test fixture + terminal output). After implementing, run stratum scan test_project/ and verify that new LEARNING & DRIFT and GOVERNANCE sections appear with ≥10 findings from learning_agent.py while existing findings remain unchanged."
```
