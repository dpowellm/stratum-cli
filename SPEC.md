# STRATUM CLI — v0.1 Build Spec (Final Merged)

You are building Stratum, a CLI that scans AI agent project directories and outputs a risk profile. `pip install stratum-cli && stratum scan .` → top risk paths in 3 seconds.

The trick: **don't parse frameworks. Parse capabilities.** Any Python file with `requests.post()` has outbound capability regardless of whether it's LangGraph, CrewAI, raw OpenAI, or a bash script. Any JSON with `"mcpServers"` is an MCP config. This works on 80%+ of repos immediately with zero framework-specific logic.

## HARD ACCEPTANCE CRITERION

**Zero findings based on keyword matching alone at CRITICAL/HIGH.**

Every CRITICAL finding must be backed exclusively by CONFIRMED evidence (import-resolved call sites or structural JSON/config facts). Every HIGH finding must be backed by CONFIRMED or PROBABLE evidence. HEURISTIC evidence (unresolved method calls, name-only keyword patterns) caps a finding at MEDIUM and bars it from top paths. The engine enforces this as a post-processing gate. No exceptions.

---

## SPEC CONTRADICTIONS & MINIMAL FIXES (from review feedback)

These are the 12 issues identified between the original spec, the operational risk patch, and the validation targets. Each bullet states the problem and the fix applied in this merged spec.

1. **`id()` in top_paths/signals split.** The original spec engine used `set(id(f) for f in top)` to partition findings into top_paths vs signals. Python `id()` is object-identity and breaks if findings are ever copied or recreated. **Fix:** Use the same stable key as deduplication: `(finding.id, tuple(sorted(finding.evidence)))`.

2. **Variable provenance for CONFIRMED on reassigned objects.** The original `_resolve_confidence` cannot confirm `server.sendmail()` or `client.chat_postMessage()` because `server`/`client` are local variables, not imports. The spec says these should be CONFIRMED. **Fix:** Build a `var_origin: dict[str, str]` map per function that records variables assigned from confirmed constructors (e.g., `server = smtplib.SMTP(...)` → `var_origin["server"] = "smtplib"`). Then `_resolve_confidence` checks `var_origin` as a third provenance source alongside `known_imports` and `alias_map`.

3. **Destructive false positives on non-DB objects.** The original spec says `.remove()` / `.delete()` / `.drop()` are HEURISTIC when no DB import exists, but if a DB import exists *anywhere in the file*, all `.remove()` calls become CONFIRMED — including `my_list.remove()`. **Fix:** CONFIRMED destructive requires *either* (a) a destructive SQL literal inside a `.execute()` call on a confirmed DB cursor, *or* (b) the call object traces to a DB import via `var_origin` or `alias_map` (e.g., `collection.delete_many()` where `collection` traces to `pymongo`). A `.remove()` on an unresolved object with a DB import elsewhere in the file is HEURISTIC, not CONFIRMED.

4. **Guardrail output_filter suppression too aggressive.** The original spec treats any `import guardrails` as `"relevant"` and fully suppresses STRATUM-001. But a bare import with no `.use()` call is not an active guardrail. **Fix:** Add `has_usage: bool` to `GuardrailSignal`. For `output_filter` type, set `has_usage=True` only if the file also contains `.use(`, `Guard()`, `guard.validate`, or `guard(`. If `has_usage=False`, treat the guardrail as `"unrelated"` (downgrade severity) rather than `"relevant"` (suppress).

5. **`stripe` missing from OUTBOUND_IMPORTS.** `test_project/tools.py` uses `stripe.Refund.create()` but `stripe` was not in `OUTBOUND_IMPORTS`. **Fix:** Add `"stripe"` to `OUTBOUND_IMPORTS`. Also add `FINANCIAL_IMPORTS` list for the operational risk patch.

6. **Semver comparison robustness.** The `_version_gte` helper uses manual tuple-int parsing, which is correct for simple semver but fragile for pre-release tags. **Fix:** Keep the manual tuple parser (avoid adding `packaging` dependency) but add explicit error handling for non-numeric segments — treat unparseable versions as vulnerable (return `False`).

7. **Top paths max count.** The spec header says "6 path rules max" for what the scanner outputs, `ScanResult.top_paths` comment says "max 5", and the engine selects `[:5]`. With operational rules added, there are now 10 rules. **Fix:** Keep `[:5]` selection for top_paths. The "6 path rules" / "10 path rules" refers to the number of rule *definitions*, not the number of findings shown. Top 5 by severity is the display limit.

8. **Risk score can exceed 100.** The scoring formula (per-finding + bonuses) easily exceeds 100. **Fix:** `min(score, 100)` as the final step.

9. **`ScanDiff | None` forward reference.** Requires `from __future__ import annotations` at the top of `models.py`. **Fix:** Add the import.

10. **`checkpoint_type` added to `ScanResult`.** The operational risk patch adds this field but it wasn't in the original models. **Fix:** Add `checkpoint_type: str = "none"` to `ScanResult`.

11. **`evaluate()` signature change.** The operational risk patch adds `checkpoint_type` as a parameter to `paths.evaluate()`. The engine must pass it through. **Fix:** Update both `Engine.evaluate()` and `paths.evaluate()` signatures.

12. **Operational rule thresholds vs test project.** STRATUM-008 requires 2+ unhandled calls. STRATUM-009 requires 2+ HTTP calls without timeout. The test project must have enough functions without try/except and without timeout to trigger these. **Fix:** The test project has 12 tool functions — the vast majority have no try/except and no timeout. Thresholds are met. The `has_error_handling` and `has_timeout` booleans on `Capability` must be computed correctly during AST scanning.

---

## THE ONLY THINGS THAT MATTER IN v0.1

### What the scanner detects (6 capability classes):

1. **MCP configs** — JSON files with `"mcpServers"`. Check: remote/no-auth, unpinned npx, credential passthrough, known CVE match.
2. **Outbound tools** — Python functions containing confirmed imports/calls from `requests`, `httpx`, `aiohttp`, `urllib`, `smtplib`, `sendgrid`, `ses`, `resend`, `slack_sdk`, `twilio`, `stripe`.
3. **Data access tools** — Python functions containing confirmed imports/calls from `psycopg2`, `sqlalchemy`, `pymongo`, `sqlite3`, `motor`, `mysql.connector`, `redis`.
4. **Code execution** — Python functions containing confirmed `subprocess`, `os.system`, `exec(`, `eval(`, `os.popen`.
5. **Destructive writes** — Python functions containing confirmed `.delete(` / `.drop(` / `DROP TABLE` / `DELETE FROM` / `TRUNCATE` / `.remove(` **where the call or string traces to a confirmed database import via var_origin, alias_map, or DB cursor convention**.
6. **Financial operations** — Python functions containing confirmed imports/calls from `stripe`, `paypalrestsdk`, `square`, `braintree`, `adyen` via direct SDK calls (not double-counted with outbound if the same function already emitted outbound for a different call site).

### What the scanner outputs (10 path rules, top 5 displayed):

**Security (existing 6):**
1. Data exfiltration path: data access + outbound, no relevant guardrail
2. Destructive action, no human gate: destructive capability + no relevant HITL
3. Code execution via agent tool: subprocess/exec in a tool function
4. Known CVE in MCP config: exact match against 2 verified CVEs
5. MCP credential exposure: production secrets passed to third-party MCP
6. MCP supply chain risk: unpinned + unverified publisher OR remote + no auth

**Operational + Business (new 4):**
7. Unvalidated financial operation: financial/outbound-to-financial SDK + no input validation + no HITL
8. No error handling on external dependencies: 2+ outbound/data_access/financial calls without try/except
9. No timeout on HTTP calls: 2+ HTTP calls (requests/httpx/aiohttp) without `timeout=` keyword
10. Volatile agent state: MemorySaver-only or no checkpointing with 3+ confirmed capabilities

### What makes it sticky:

- Local scan history (`.stratum/history.jsonl`)
- Risk score delta on repeat runs
- `--ci` regression gate: fail build if new CRITICALs or risk score increase >10

### What feeds the risk map:

- Anonymized telemetry profile after every scan
- Counts and ratios only — capability type distribution, trust level distribution, guardrail presence, risk score, error handling rate, timeout rate, checkpoint type

---

## PROJECT STRUCTURE

```
stratum/
├── pyproject.toml
├── README.md
├── stratum/
│   ├── __init__.py
│   ├── cli.py              # Click entry point
│   ├── scanner.py           # Orchestrator
│   ├── models.py            # All dataclasses
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── capabilities.py  # THE core: AST-based capability detection on any .py file
│   │   ├── mcp.py           # MCP JSON config parser
│   │   └── env.py           # .env + hardcoded secret scanner
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── engine.py        # Severity gating + top-5 selection
│   │   └── paths.py         # All 10 path rules
│   ├── knowledge/
│   │   ├── __init__.py
│   │   └── db.py            # 2 CVEs + 4 patterns + safe publishers + capability patterns
│   ├── output/
│   │   ├── __init__.py
│   │   └── terminal.py      # Rich output
│   └── telemetry/
│       ├── __init__.py
│       ├── profile.py       # Anonymized telemetry builder
│       └── history.py       # Local JSONL history + diff
├── risk_map/
│   ├── __init__.py
│   ├── ingestion.py         # Ingest telemetry profiles
│   ├── aggregator.py        # Aggregate across scans
│   ├── intelligence.py      # Derive risk intelligence from aggregated data
│   └── models.py            # Risk map data structures
└── test_project/
    ├── agent.py
    ├── tools.py
    ├── .cursor/mcp.json
    ├── .env
    └── README.md
```

~15 files. Not 30.

---

## MODELS (`stratum/models.py`)

Must begin with `from __future__ import annotations` for forward-reference support.

```python
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"    # import-resolved call site or structural config fact
    PROBABLE = "probable"      # strong inference (e.g. SQL keyword in function with DB import, but not inside .execute())
    HEURISTIC = "heuristic"    # unresolved object method or bare keyword — max MEDIUM, never in top paths


class RiskCategory(str, Enum):
    SECURITY = "security"
    OPERATIONAL = "operational"
    BUSINESS = "business"


class TrustLevel(str, Enum):
    PRIVILEGED = "privileged"  # code exec, infra
    RESTRICTED = "restricted"  # PII, customer data, credentials, money
    INTERNAL = "internal"      # internal DBs
    EXTERNAL = "external"      # outbound APIs, email, messaging
    PUBLIC = "public"          # search, public data


@dataclass
class Capability:
    """A dangerous capability found in a Python function.

    confidence determines how this was detected:
    - CONFIRMED: import resolved to call site (e.g. `import requests` + `requests.post()`)
    - PROBABLE: strong inference (e.g. SQL DELETE keyword in function body that has a DB import)
    - HEURISTIC: unresolved method (e.g. `.send()` on unknown object) — max severity MEDIUM
    """
    kind: str               # "outbound" | "data_access" | "code_exec" | "destructive" | "file_system" | "financial"
    confidence: Confidence  # HOW this was detected — determines max severity
    function_name: str
    source_file: str
    line_number: int
    evidence: str           # e.g. "import smtplib → smtplib.SMTP" or "subprocess.run(command, shell=True)"
    library: str            # e.g. "smtplib", "psycopg2", "subprocess", "" if heuristic
    trust_level: TrustLevel
    has_error_handling: bool = False  # is the dangerous call inside try/except?
    has_timeout: bool = False         # does the HTTP call specify timeout= kwarg?
    has_input_validation: bool = False  # any validation before the dangerous call?


@dataclass
class MCPServer:
    name: str
    source_file: str
    command: str = ""
    url: str = ""
    args: list[str] = field(default_factory=list)
    env_vars_passed: list[str] = field(default_factory=list)  # names only, NEVER values
    transport: str = "unknown"  # stdio | sse | http
    is_remote: bool = False
    has_auth: bool = False
    npm_package: str = ""
    package_version: str = ""   # empty = unpinned
    is_known_safe: bool = False


@dataclass
class GuardrailSignal:
    """Evidence of guardrails/safety patterns found in the project."""
    kind: str               # "input_filter" | "output_filter" | "hitl" | "rate_limit" | "validation"
    source_file: str
    line_number: int
    detail: str             # "send_email,delete_record" for hitl (tool names from interrupt_before)
                            # "InputGuardrail" | "Guard().use()" etc for others
    covers_tools: list[str] = field(default_factory=list)
    # For hitl: extracted tool names from interrupt_before=[...] / interrupt_after=[...]
    # For others: empty (applies broadly)
    has_usage: bool = True  # NEW: False if output_filter is import-only with no .use()/.Guard() evidence


@dataclass
class Finding:
    id: str                 # STRATUM-001 through STRATUM-010
    severity: Severity
    confidence: Confidence
    category: RiskCategory
    title: str
    path: str               # THE risk path: "A → B → consequence"
    description: str        # what breaks, dev language
    evidence: list[str] = field(default_factory=list)   # file:line refs
    scenario: str = ""      # vivid, grounded
    business_context: str = ""  # secondary — only when confirmed dangerous capability
    remediation: str = ""   # pasteable code
    effort: str = "low"     # low | med | high
    references: list[str] = field(default_factory=list)  # verified URLs only
    owasp_id: str = ""      # ASI01-ASI10


@dataclass
class ScanResult:
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    directory: str = ""
    capabilities: list[Capability] = field(default_factory=list)
    mcp_servers: list[MCPServer] = field(default_factory=list)
    guardrails: list[GuardrailSignal] = field(default_factory=list)
    env_vars: list[str] = field(default_factory=list)  # names only

    top_paths: list[Finding] = field(default_factory=list)    # max 5
    signals: list[Finding] = field(default_factory=list)      # everything else

    risk_score: int = 0
    total_capabilities: int = 0
    outbound_count: int = 0
    data_access_count: int = 0
    code_exec_count: int = 0
    destructive_count: int = 0
    financial_count: int = 0
    mcp_server_count: int = 0
    guardrail_count: int = 0
    has_any_guardrails: bool = False
    checkpoint_type: str = "none"  # "durable" | "memory_only" | "none"

    diff: ScanDiff | None = None


@dataclass
class ScanDiff:
    previous_risk_score: int = 0
    risk_score_delta: int = 0
    new_finding_ids: list[str] = field(default_factory=list)
    resolved_finding_ids: list[str] = field(default_factory=list)


@dataclass
class TelemetryProfile:
    """Anonymized. No source code, secrets, paths, function names, env values."""
    scan_id: str = ""
    timestamp: str = ""
    version: str = "0.1.0"

    # Capability counts
    total_capabilities: int = 0
    capability_distribution: dict[str, int] = field(default_factory=dict)
    # e.g. {"outbound": 3, "data_access": 2, "code_exec": 1, "financial": 1}
    trust_level_distribution: dict[str, int] = field(default_factory=dict)
    # e.g. {"EXTERNAL": 3, "INTERNAL": 2, "PRIVILEGED": 1}

    # Trust boundary crossings (the key risk map signal)
    trust_crossings: dict[str, int] = field(default_factory=dict)
    # e.g. {"INTERNAL→EXTERNAL": 2}
    total_trust_crossings: int = 0

    # MCP
    mcp_server_count: int = 0
    mcp_remote_count: int = 0
    mcp_auth_ratio: float = 0.0
    mcp_pinned_ratio: float = 0.0

    # Guardrails
    guardrail_count: int = 0
    has_any_guardrails: bool = False
    guardrail_types: list[str] = field(default_factory=list)

    # Risk
    risk_score: int = 0
    finding_severities: dict[str, int] = field(default_factory=dict)
    finding_confidences: dict[str, int] = field(default_factory=dict)

    # Env
    env_var_count: int = 0
    has_env_in_gitignore: bool = False

    # Operational signals (NEW)
    error_handling_rate: float = 0.0       # % of external calls with try/except
    timeout_rate: float = 0.0              # % of HTTP calls with timeout
    checkpoint_type: str = "none"          # "durable" | "memory_only" | "none"
    has_financial_tools: bool = False       # any financial capability detected
    financial_validation_rate: float = 0.0  # % of financial tools with validation
```

---

## CLI (`stratum/cli.py`)

Click CLI. Minimal.

```
stratum scan [PATH] [--verbose] [--json] [--ci] [--no-telemetry]
```

- Default PATH: `.`
- Default: Rich terminal, top paths + compact signals
- `--verbose`: expand signals with full detail
- `--json`: JSON to stdout instead of Rich
- `--ci`: JSON to stdout. Exit 1 if new CRITICAL since last scan or risk score increased >10. Exit 2 if new HIGH. Exit 0 otherwise. First run: exit 1 if any CRITICAL, exit 2 if any HIGH.
- `--no-telemetry`: skip `.stratum/last-scan.json` (history still writes)

---

## SCANNER (`stratum/scanner.py`)

`scan(path: str) -> ScanResult`:

1. Walk directory. Skip `.git`, `node_modules`, `.venv`, `__pycache__`, `.stratum`, `*.pyc`. Best-effort `.gitignore`: read file if present, apply simple line-by-line matching (literal paths, `*` globs, trailing `/` for dirs). Don't try to be git-perfect.

2. For each `.py` file: run `capabilities.scan_python_file()` → list of `Capability` and `GuardrailSignal`.

3. For each `.json` file: try `mcp.parse_mcp_configs()` → list of `MCPServer` (returns empty if not MCP config).

4. For `.env*` files and `.py` files: run `env.scan_env()` → env var names + secret findings.

5. **Checkpoint detection (NEW):** For each `.py` file content, check for checkpoint patterns:
   - If content contains `"PostgresSaver"` or `"SqliteSaver"` or `"RedisSaver"` (and `"langgraph.checkpoint"`) → set `checkpoint_type = "durable"`
   - Else if content contains `"MemorySaver"` (and `"langgraph.checkpoint"`) and not already durable → set `checkpoint_type = "memory_only"`
   - Durable takes precedence: if any file has durable, the project is durable.

6. Collect all capabilities, MCP servers, guardrails, env vars.

7. Run `engine.evaluate(capabilities, mcp_servers, guardrails, env_vars, env_findings, checkpoint_type)` → top_paths, signals.

8. Calculate risk score:
   - Per finding: CRITICAL=25, HIGH=15, MEDIUM=8, LOW=3
   - Bonus: zero guardrails with ≥3 capabilities → +15
   - Bonus: Known CVE MCP → +20
   - Bonus: financial tools + no HITL + no validation → +10
   - Bonus: zero error handling across ≥3 external calls → +5
   - **Cap: `min(score, 100)`**

9. Load `.stratum/history.jsonl`, compute diff.

10. Save history (always). Save telemetry profile (unless `--no-telemetry`).

11. Return ScanResult.

---

## PARSERS

### `parsers/capabilities.py` — THE CORE

This is the whole scanner's value. It reads Python files and finds dangerous function-level capabilities via AST. It does NOT know what LangGraph or CrewAI is. If a function has `subprocess.run()`, we find it.

```python
def scan_python_file(file_path: str, content: str) -> tuple[list[Capability], list[GuardrailSignal]]:
    """Scan a Python file for dangerous capabilities and guardrail signals."""
```

**Step 1: Parse AST.** `ast.parse(content)` wrapped in try/except (return empty on failure).

**Step 1b: Collect module-level imports.**
Walk the module's top-level `ast.Import` and `ast.ImportFrom` nodes. Build `file_imports: set[str]` containing the names available in module scope:
```python
# import requests → file_imports.add("requests")
# import subprocess → file_imports.add("subprocess")
# from slack_sdk import WebClient → file_imports.add("slack_sdk"); also note WebClient → slack_sdk
# from psycopg2 import connect → file_imports.add("psycopg2")
```
Also build `import_alias_map: dict[str, str]` for `from X import Y` cases:
```python
# from slack_sdk import WebClient → import_alias_map["WebClient"] = "slack_sdk"
# from email.mime.text import MIMEText → import_alias_map["MIMEText"] = "email.mime.text"
```

**Step 2: Find all function definitions** (`ast.FunctionDef`, `ast.AsyncFunctionDef`). Include top-level functions AND methods inside classes. These are potential "tools" — but we don't care whether they're decorated with `@tool` or not.

**Step 3: For each function, walk the body and detect capabilities.**

For each function, first collect `local_imports: set[str]` from `ast.Import` / `ast.ImportFrom` nodes inside the function body (same logic as step 1b but scoped to the function). Merge into a combined `known_imports = file_imports | local_imports`. Similarly merge `alias_map = file_alias_map | local_alias_map`.

#### Step 3a: Build `var_origin` map (NEW — critical for correctness)

Before walking call nodes, iterate all `ast.Assign` nodes in the function body to build `var_origin: dict[str, str]` — a map from variable names to their origin module.

The `_build_var_origin` function processes assignments like:

```python
# server = smtplib.SMTP(...)     → var_origin["server"] = "smtplib"
# client = WebClient(...)         → var_origin["client"] = "slack_sdk" (via alias_map)
# conn = psycopg2.connect(...)   → var_origin["conn"] = "psycopg2"
# cursor = conn.cursor()         → var_origin["cursor"] = "psycopg2" (via var_origin["conn"])
# refund = stripe.Refund.create() → var_origin["refund"] = "stripe"
```

Logic for `_resolve_call_origin(call_node, known_imports, alias_map, var_origin) -> str`:
- If `call.func` is `ast.Attribute` with `ast.Name` value:
  - `obj.method()`: if `obj` in `known_imports` → return `obj`. If `obj` in `alias_map` → return top module of `alias_map[obj]`. If `obj` in `var_origin` → return `var_origin[obj]`.
- If `call.func` is `ast.Name`:
  - `Name()`: if `Name` in `alias_map` → return top module of `alias_map[Name]`. If `Name` in `known_imports` → return `Name`.
- Return `""` otherwise.

**This is the key fix for send_email/send_slack_message.** When `server = smtplib.SMTP(...)` is assigned, `var_origin["server"] = "smtplib"`. Then `server.sendmail(...)` resolves via `var_origin` to `smtplib` → CONFIRMED outbound. Same for `client = WebClient(...)` → `var_origin["client"] = "slack_sdk"` → `client.chat_postMessage(...)` is CONFIRMED.

#### Step 3b: Walk call nodes with updated confidence resolution

Then walk all nodes in the function body via `ast.walk()`.

### THE CONFIDENCE CONTRACT (UPDATED)

The `_resolve_confidence` logic now checks **three** provenance sources, not two:

```python
def _resolve_confidence(obj_name: str, method: str,
                        known_imports: set[str],
                        alias_map: dict[str, str],
                        var_origin: dict[str, str]) -> tuple[Confidence, str]:
    """Determine confidence and origin module for obj.method() calls.

    Checks three provenance sources in order:
    1. known_imports: obj is a directly imported module
    2. alias_map: obj was imported via 'from X import obj'
    3. var_origin: obj was assigned from a confirmed constructor

    Returns (confidence, origin_module).
    """
    if not obj_name:
        return Confidence.HEURISTIC, ""

    # Source 1: Direct import (import requests → requests.post())
    if obj_name in known_imports:
        return Confidence.CONFIRMED, obj_name

    # Source 2: Alias (from slack_sdk import WebClient → WebClient in alias_map)
    if obj_name in alias_map:
        top_module = alias_map[obj_name].split(".")[0]
        return Confidence.CONFIRMED, top_module

    # Source 3: Variable provenance (server = smtplib.SMTP() → server in var_origin)
    if obj_name in var_origin:
        return Confidence.CONFIRMED, var_origin[obj_name]

    # Source 4: DB cursor convention (cursor/conn/session with DB import in scope)
    if obj_name in DB_CURSOR_NAMES:
        if any(lib.split(".")[0] in known_imports for lib in DATA_ACCESS_IMPORTS):
            db_lib = first_db_import(known_imports)
            return Confidence.CONFIRMED, db_lib

    # Unresolved → HEURISTIC
    return Confidence.HEURISTIC, ""
```

Where `DB_CURSOR_NAMES = {"cursor", "conn", "session", "collection", "db", "client"}`.

**IMPORTANT:** The `"client"` name in `DB_CURSOR_NAMES` creates an ambiguity — `client` could be a DB client or an outbound client. Resolution: `var_origin` takes precedence. If `client = WebClient(...)` → `var_origin["client"] = "slack_sdk"` → outbound, not DB. The DB cursor convention is a fallback only when `var_origin` has no entry for the variable.

So the actual resolution order for Step 3b when checking `obj.method()` is:
1. Is `obj` in `known_imports`? → CONFIRMED, origin = obj
2. Is `obj` in `alias_map`? → CONFIRMED, origin = alias_map value
3. Is `obj` in `var_origin`? → CONFIRMED, origin = var_origin value
4. Is `obj` in `DB_CURSOR_NAMES` AND any DB import in `known_imports`? → CONFIRMED, origin = first DB import
5. None of the above → HEURISTIC

### Detection patterns — confidence-annotated

**Outbound (trust: EXTERNAL):**

CONFIRMED detections (import resolved to call):
```python
# import requests → requests.get(...), requests.post(...)
# import httpx → httpx.get(...), httpx.post(...), httpx.Client(...)
# import aiohttp → aiohttp.ClientSession(...)
# from urllib.request import urlopen → urlopen(...)
# import smtplib → smtplib.SMTP(...), then server.sendmail(...)
#   ↑ server = smtplib.SMTP() → var_origin["server"] = "smtplib" → server.sendmail() CONFIRMED
# import sendgrid → sendgrid.SendGridAPIClient(...)
# import resend → resend.Emails.send(...)
# from slack_sdk import WebClient → WebClient(...), then client.chat_postMessage(...)
#   ↑ client = WebClient() → alias_map["WebClient"] = "slack_sdk"
#     → var_origin["client"] = "slack_sdk" → client.chat_postMessage() CONFIRMED
# from twilio.rest import Client → Client(...)
# import stripe → stripe.Refund.create(...), stripe.Charge.create(...)
#   ↑ stripe is in known_imports → stripe.Refund is attribute chain → CONFIRMED
#   ↑ Note: stripe.Refund.create() is Attribute(Attribute(Name("stripe"), "Refund"), "create")
#     The AST node's func.value is itself an Attribute, not a Name.
#     Must handle this case: if func.value is Attribute with Name value, 
#     resolve the root Name. stripe.Refund.create() root = "stripe".
```

HEURISTIC detections (unresolved object):
```python
# some_object.post(data)     — no idea what some_object is → HEURISTIC
# response.send(msg)         — could be anything → HEURISTIC
# self.mailer.send_message() — can't resolve self → HEURISTIC
```

**Outbound method names to match:**
```python
OUTBOUND_METHODS = ["post", "get", "put", "patch", "delete", "send", "sendmail",
                    "send_message", "chat_postMessage", "create"]
```

Note: `"create"` is in OUTBOUND_METHODS because `stripe.Refund.create()`, `stripe.Charge.create()` etc. are the primary financial SDK patterns. The confidence contract ensures this only fires when the object traces to an outbound/financial import — `my_list.create()` would be HEURISTIC.

**Data access (trust: INTERNAL):**

CONFIRMED:
```python
# import psycopg2 → psycopg2.connect(...), cursor.execute(...)
#   ↑ cursor convention: if psycopg2 in imports, cursor.execute() is CONFIRMED
# import sqlalchemy → create_engine(...), session.query(...)
# import pymongo → pymongo.MongoClient(...), collection.find(...)
# import sqlite3 → sqlite3.connect(...)
# import motor, import redis, import mysql.connector
```

HEURISTIC:
```python
# some_object.fetchone()  — no DB import in scope → HEURISTIC
# cursor.execute(...)     — BUT no DB import anywhere → HEURISTIC
```

Trust level: ALWAYS `TrustLevel.INTERNAL` for data_access. Do NOT promote to RESTRICTED based on function name keywords.

**Data access method names to match:**
```python
DATA_ACCESS_METHODS = ["execute", "query", "find", "find_one", "find_many",
                       "fetchone", "fetchall", "fetchmany", "connect"]
```

**Code execution (trust: PRIVILEGED):**

CONFIRMED:
```python
# import subprocess → subprocess.run(...), subprocess.call(...), subprocess.Popen(...)
# import os → os.system(...), os.popen(...)
# exec(...)  — builtin, always CONFIRMED (check via ast.Name(id="exec"))
# eval(...)  — builtin, always CONFIRMED (check via ast.Name(id="eval"))
```

CRITICAL IMPLEMENTATION NOTE: `exec(` must be detected via `ast.Name(id="exec")` on an `ast.Call` node — NOT as a substring match, which would falsely match `cursor.execute(...)`. Same for `eval(` vs `.evaluate()`.

`shell=True` keyword argument: this is a modifier that adds evidence to an already-detected `subprocess` capability. It does NOT create a capability by itself. Check for `shell=True` via `any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)`.

**Code exec patterns:**
```python
CODE_EXEC_FUNCTIONS = {
    "subprocess": ["run", "call", "Popen", "check_output", "check_call"],
    "os": ["system", "popen"],
}
CODE_EXEC_BUILTINS = {"exec", "eval"}
```

**Destructive writes (trust: INTERNAL) — UPDATED RULES:**

The destructive detection has been tightened to prevent false positives on non-DB objects.

**CONFIRMED** (requires BOTH: DB provenance on the object AND destructive action):

Path A — destructive SQL literal inside `.execute()` on a confirmed DB cursor:
```python
# import psycopg2 + cursor.execute(f"DELETE FROM {table}...")
#   ↑ cursor traces to DB import (convention or var_origin) + string literal contains DELETE FROM
# import psycopg2 + cursor.execute(f"DROP TABLE {table}")
# Confidence: CONFIRMED (DB cursor proven + destructive SQL string inside execute())
```

Path B — destructive method call on an object that traces to a DB import:
```python
# import pymongo + collection = db.get_collection("users") + collection.delete_many(...)
#   ↑ collection traces via var_origin to pymongo → CONFIRMED destructive
# import pymongo + collection.delete_many(...) where collection is in DB_CURSOR_NAMES
#   and pymongo is in known_imports → CONFIRMED (cursor convention)
```

**PROBABLE** (DB import present, destructive SQL literal in function body, but NOT inside a confirmed `.execute()` call):
```python
# import psycopg2 in file + function has string "DELETE FROM" but NOT inside cursor.execute()
# → PROBABLE (the function probably does destructive SQL, but we can't prove the string is executed)
```

**HEURISTIC** (the critical false-positive prevention case):
```python
# my_list.remove(item)    — no DB provenance on my_list → HEURISTIC? No — SKIP entirely.
# cache.delete("key")     — no DB import → SKIP entirely (not even HEURISTIC)
# some_object.drop()      — no DB import → SKIP entirely
```

**IMPORTANT RULE:** If a function has a DB import in scope but the `.remove()` / `.delete()` / `.drop()` call is on an object that does NOT trace to a DB import via var_origin, alias_map, or cursor convention, the call is **HEURISTIC** if there is a DB import somewhere (because it *might* be DB-related), or **skipped entirely** if there is no DB import at all. A `.remove()` on `my_list` in a function with no DB imports produces zero capabilities.

**Destructive method names:**
```python
DESTRUCTIVE_METHODS = ["delete", "delete_one", "delete_many", "drop", "remove"]
DESTRUCTIVE_SQL_KEYWORDS = ["DELETE FROM", "DROP TABLE", "DROP DATABASE", "TRUNCATE"]
```

**Financial operations (trust: RESTRICTED) — NEW:**

CONFIRMED:
```python
# import stripe → stripe.Refund.create(...), stripe.Charge.create(...),
#   stripe.PaymentIntent.create(...), stripe.Transfer.create(...)
# import paypalrestsdk → paypalrestsdk.Payment(...), .execute()
# from square.client import Client → Client(...)
# import braintree → braintree.Transaction.sale(...)
```

**Financial imports:**
```python
FINANCIAL_IMPORTS = ["stripe", "paypalrestsdk", "square", "braintree", "adyen"]
```

**Do NOT double-count:** If a function already produces an `outbound` capability (e.g. it uses `requests.post` to hit a payment API), don't also emit `financial` for the same function unless there's a separate financial SDK call. The rule is: one capability per distinct dangerous call site per function. In practice, `stripe.Refund.create()` is classified as `financial` (kind), not `outbound`, because `stripe` is in `FINANCIAL_IMPORTS`. But if the same function also has `requests.post()`, that's a separate `outbound` capability for the same function — both are emitted because they are different call sites.

Trust level: `TrustLevel.RESTRICTED` for financial (money movement).

**File system (trust: INTERNAL):**
```python
# open(...) — builtin, CONFIRMED
# import pathlib → Path(...), CONFIRMED
# import os → os.remove(...), os.unlink(...) — CONFIRMED
# import shutil → shutil.rmtree(...) — CONFIRMED
```

(File system capabilities are detected but no path rule fires on them alone in v0.1.)

#### Step 3c: Per-capability metadata (NEW)

For every Capability emitted, compute three boolean metadata fields:

**`has_error_handling`:** Check if the dangerous call at `call_line` is structurally contained inside a `try/except` block.

```python
def _has_error_handling(func_node, call_line: int) -> bool:
    """Check if the call at call_line is inside a try/except block.

    Walk the function body looking for ast.Try nodes.
    For each Try, check if call_line falls within the line range of the try body
    (from first statement line to last statement end_lineno).
    Deliberately simple: bare `except: pass` still counts as "handled" for v0.1.
    We're detecting the complete ABSENCE of error handling, not auditing quality.
    """
```

**`has_timeout`:** For CONFIRMED outbound capabilities using `requests`, `httpx`, or `aiohttp`, check if the ast.Call node has a `timeout` keyword argument:

```python
def _has_timeout(node: ast.Call) -> bool:
    """Check if an HTTP call has a timeout parameter."""
    return any(kw.arg == "timeout" for kw in node.keywords)
```

Only set `has_timeout=True` for calls where the library is `"requests"`, `"httpx"`, or `"aiohttp"`. Other outbound libraries (smtp, slack, etc.) don't have the same timeout semantics.

**`has_input_validation`:** For functions containing a CONFIRMED financial capability, check for validation patterns in the function body BEFORE the dangerous call:

```python
def _has_input_validation(func_node) -> bool:
    """Check if function has any input validation before dangerous calls.

    Looks for:
    - isinstance() calls (ast.Call with ast.Name(id="isinstance"))
    - Comparison operators (ast.Compare) involving function parameters
    - Pydantic model_validate / TypeAdapter
    - assert statements (ast.Assert)
    - if/raise patterns (ast.If containing ast.Raise in body)

    Deliberately broad: detecting COMPLETE ABSENCE of validation,
    not auditing correctness.
    """
```

**Step 4: Detect guardrail signals** (project-wide, not per-function):

```python
# LangGraph HITL — IMPORTANT: extract tool names from the list
"interrupt_before" / "interrupt_after"
```
When `interrupt_before=[...]` or `interrupt_after=[...]` is detected:
- Parse the list contents from the AST (it's an `ast.List` node containing `ast.Constant` strings)
- Store: `GuardrailSignal(kind="hitl", covers_tools=["send_email", "delete_record"], detail="interrupt_before")`
- If the list can't be parsed (dynamic variable), store `covers_tools=[]` (broad HITL — assume it covers everything)

```python
# Guardrail libraries — with has_usage check for output_filter (NEW)
"from guardrails" / "import guardrails"   → GuardrailSignal(kind="output_filter", has_usage=???)
    # has_usage = True ONLY if the file also contains ".use(" or "Guard()" or "guard.validate" or "guard("
    # has_usage = False if it's just the import with no usage evidence
"from nemoguardrails"                     → GuardrailSignal(kind="input_filter")
"InputGuardrail" / "OutputGuardrail"      → GuardrailSignal(kind matching type)
"from llm_guard"                          → GuardrailSignal(kind="output_filter")

# Rate limiting
"recursion_limit" / "max_iterations" / "max_turns"  → GuardrailSignal(kind="rate_limit")

# Input validation in tool functions
"isinstance(" / "model_validate(" / "TypeAdapter" / "re.match(" / "re.search("
    → GuardrailSignal(kind="validation")
```

Guardrail detection uses keyword/import matching but that's fine — guardrails are not findings, they're mitigating evidence.

#### Handling `stripe.Refund.create()` — chained attribute AST pattern

The call `stripe.Refund.create(...)` has the AST structure:
```
Call(
  func=Attribute(
    value=Attribute(
      value=Name(id="stripe"),
      attr="Refund"
    ),
    attr="create"
  )
)
```

The `func.value` is an `Attribute`, not a `Name`. Standard `_resolve_confidence` checks `isinstance(node.func.value, ast.Name)` — this fails for chained attributes. **Fix:** When `node.func.value` is `ast.Attribute`, recursively resolve to the root `ast.Name`:

```python
def _get_root_name(node) -> str:
    """Recursively resolve chained attributes to the root Name.
    stripe.Refund.create() → "stripe"
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _get_root_name(node.value)
    return ""
```

Then when checking an `ast.Call` whose `func` is `ast.Attribute`:
1. First try `isinstance(func.value, ast.Name)` → standard resolution
2. If `func.value` is also `ast.Attribute`, call `_get_root_name(func.value)` → get root object → resolve via known_imports/alias_map/var_origin

### `parsers/mcp.py`

```python
def parse_mcp_configs(directory: str) -> list[MCPServer]:
    """Find and parse all MCP config files in the project."""
```

Look for these files (relative to scan directory):
- `claude_desktop_config.json`
- `.cursor/mcp.json`
- `.vscode/mcp.json`
- `mcp.json`
- Any `.json` file containing `"mcpServers"` key (scan top-level JSON files only, don't recurse deep)

For each `mcpServers` entry:
- **Name:** the key
- **Command + args:** from `"command"` and `"args"` fields
- **URL:** from `"url"` field (SSE/HTTP transport)
- **Env vars:** keys from `"env"` dict — NAMES ONLY, never values
- **Transport:** `"stdio"` if command present, `"sse"` if url with `/sse`, `"http"` otherwise
- **is_remote:** True if `url` field present, or if args contain `https://`
- **has_auth:** True if any env var name contains TOKEN, KEY, SECRET, AUTH, PASSWORD, OAUTH, BEARER
- **npm_package:** extract from `npx <package>` in command/args. If `npx @scope/name@version`, extract package and version. If `npx name` without `@version`, version is empty (unpinned).
- **is_known_safe:** check npm_package prefix against `KNOWN_SAFE_PUBLISHERS`

All MCP findings use `Confidence.CONFIRMED` because they're based on structural JSON facts.

### `parsers/env.py`

```python
def scan_env(directory: str, py_file_paths: list[str]) -> tuple[list[str], list[Finding]]:
    """Scan for env var exposure. Returns (env_var_names, findings)."""
```

- Find `.env` files. Extract var names. Flag well-known sensitive patterns.
- Check if `.env` is in `.gitignore`. If not → finding (MEDIUM, confirmed).
- Scan `.py` files for hardcoded secrets via regex:
  - `sk-[a-zA-Z0-9_-]{20,}` (OpenAI)
  - `sk_live_[a-zA-Z0-9]+` (Stripe)
  - `Bearer [a-zA-Z0-9_-]{20,}`
  - `postgresql://[^:]+:[^@]+@` (connection string with password)
  - `mongodb://[^:]+:[^@]+@`

Env findings are always MEDIUM severity, CONFIRMED confidence.

---

## KNOWLEDGE (`knowledge/db.py`)

Everything in one file. Small.

```python
# === 2 verified CVEs ===
KNOWN_CVES: dict[str, dict] = {
    "mcp-remote": {
        "cve": "CVE-2025-6514",
        "cvss": 9.6,
        "summary": "RCE via crafted MCP server responses.",
        "affected": "<0.1.9",
        "fixed": "0.1.9",
        "urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
        ],
    },
    "copilot-echoleak": {
        "cve": "CVE-2025-32711",
        "cvss": 8.4,
        "summary": "Data exfiltration via cross-tool prompt injection.",
        "urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-32711",
            "https://embracethered.com/blog/posts/2024/m365-copilot-echo-leak/",
        ],
    },
}

# === Attack patterns ===
KNOWN_PATTERNS: dict[str, dict] = {
    "mcp-tool-poisoning": {...},
    "mcp-rug-pull": {...},
    "mcp-credential-passthrough": {...},
    "cross-tool-exfiltration": {...},
}

# === Safe MCP publishers ===
KNOWN_SAFE_PUBLISHERS: list[str] = [
    "@modelcontextprotocol/", "@anthropic/", "@openai/",
    "@google/", "@microsoft/", "@docker/", "@stripe/", "@github/",
]

# === OWASP Agentic Top 10 ===
OWASP_AGENTIC: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Agent Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

# === Capability detection patterns ===

OUTBOUND_IMPORTS = ["requests", "httpx", "aiohttp", "urllib.request", "smtplib",
                    "sendgrid", "resend", "slack_sdk", "twilio", "stripe"]

OUTBOUND_METHODS = ["post", "get", "put", "patch", "delete", "send", "sendmail",
                    "send_message", "chat_postMessage", "create"]

DATA_ACCESS_IMPORTS = ["psycopg2", "sqlalchemy", "pymongo", "sqlite3", "motor",
                       "mysql.connector", "redis"]

DATA_ACCESS_METHODS = ["execute", "query", "find", "find_one", "find_many",
                       "fetchone", "fetchall", "fetchmany", "connect"]

DB_CURSOR_NAMES = {"cursor", "conn", "session", "collection", "db", "client"}

CODE_EXEC_FUNCTIONS = {
    "subprocess": ["run", "call", "Popen", "check_output", "check_call"],
    "os": ["system", "popen"],
}
CODE_EXEC_BUILTINS = {"exec", "eval"}

DESTRUCTIVE_SQL_KEYWORDS = ["DELETE FROM", "DROP TABLE", "DROP DATABASE", "TRUNCATE"]
DESTRUCTIVE_METHODS = ["delete", "delete_one", "delete_many", "drop", "remove"]

FINANCIAL_IMPORTS = ["stripe", "paypalrestsdk", "square", "braintree", "adyen"]

SENSITIVE_ENV_PATTERNS = ["_API_KEY", "_SECRET", "DATABASE_URL", "_PASSWORD",
                          "_TOKEN", "STRIPE_", "AWS_SECRET", "OPENAI_API",
                          "ANTHROPIC_API"]
```

---

## RULES

### `rules/engine.py`

```python
def _derive_finding_confidence(*capabilities: Capability) -> Confidence:
    """A chain is as strong as its weakest link.

    If ANY input capability is HEURISTIC → finding is HEURISTIC → max MEDIUM.
    If ANY is PROBABLE → finding is PROBABLE → max HIGH.
    Only all-CONFIRMED → finding can be CRITICAL.
    """
```

```python
def _gate_severity(finding: Finding) -> Finding:
    """Post-processing gate that ENFORCES the acceptance criterion.

    Called on every finding after all rules have run. No exceptions.
    HEURISTIC → max MEDIUM. PROBABLE → max HIGH. Only CONFIRMED → CRITICAL.

    MUST log every invocation for auditability:
        logger.info("_gate_severity: %s severity=%s→%s confidence=%s", ...)
    """
```

```python
def _finding_key(f: Finding) -> tuple[str, tuple[str, ...]]:
    """Stable dedup/identity key. Used for BOTH dedup AND top/signal split."""
    return (f.id, tuple(sorted(f.evidence)))
```

```python
class Engine:
    def evaluate(self, capabilities, mcp_servers, guardrails, env_vars, 
                 env_findings, checkpoint_type) -> tuple[list[Finding], list[Finding]]:
        all_findings = []

        # Path rules (all 10)
        all_findings.extend(paths.evaluate(capabilities, mcp_servers, guardrails, checkpoint_type))

        # Env findings (from env scanner)
        all_findings.extend(env_findings)

        # ENFORCE acceptance criterion: gate every finding
        for i, f in enumerate(all_findings):
            all_findings[i] = _gate_severity(f)
            # ^^^ _gate_severity logs every call

        # Deduplicate by stable key
        seen = set()
        deduped = []
        for f in all_findings:
            key = _finding_key(f)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        # Sort: severity desc → confidence desc → len(evidence) desc
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        confidence_order = {Confidence.CONFIRMED: 0, Confidence.PROBABLE: 1, Confidence.HEURISTIC: 2}
        deduped.sort(key=lambda f: (severity_order[f.severity], confidence_order[f.confidence], -len(f.evidence)))

        # Top paths: first 5 that are NOT heuristic-only
        # Uses _finding_key for the split — NOT Python id()
        top = [f for f in deduped if f.confidence != Confidence.HEURISTIC][:5]
        top_keys = {_finding_key(f) for f in top}
        signals = [f for f in deduped if _finding_key(f) not in top_keys]

        return top, signals
```

### `rules/paths.py` — All 10 rules

```python
def evaluate(capabilities, mcp_servers, guardrails, checkpoint_type) -> list[Finding]:
    findings = []

    # Security paths (6)
    findings.extend(_check_data_exfil(capabilities, guardrails))
    findings.extend(_check_destructive(capabilities, guardrails))
    findings.extend(_check_code_exec(capabilities))
    findings.extend(_check_mcp_cve(mcp_servers))
    findings.extend(_check_mcp_credentials(mcp_servers))
    findings.extend(_check_mcp_supply_chain(mcp_servers))

    # Operational + business paths (4, NEW)
    findings.extend(_check_unvalidated_financial(capabilities, guardrails))
    findings.extend(_check_no_error_handling(capabilities))
    findings.extend(_check_no_timeout(capabilities))
    findings.extend(_check_volatile_state(checkpoint_type, capabilities))

    return findings
```

#### Shared helpers

```python
def _version_gte(version_str: str, fixed_str: str) -> bool:
    """Semver comparison: True if version_str >= fixed_str.

    Uses numeric tuple comparison, NOT string comparison.
    "0.10.0" >= "0.1.9" → True.
    Non-numeric segments (pre-release tags) → return False (assume vulnerable).
    """
    try:
        def parse(v: str) -> tuple[int, ...]:
            return tuple(int(x) for x in v.strip().split("."))
        return parse(version_str) >= parse(fixed_str)
    except (ValueError, AttributeError):
        return False
```

```python
def _has_relevant_guard(guardrails, tool_names, guard_kinds) -> str:
    """Check guardrails for relevance to specific tools.

    Returns:
      "relevant" — a guardrail specifically covers these tools AND has usage → suppress
      "unrelated" — guardrails exist but don't cover, or import-only with no usage → downgrade
      "none" — no guardrails at all → full severity

    CRITICAL FIX: For output_filter guardrails, check has_usage.
    If has_usage=False (import-only, no .use() evidence), treat as "unrelated",
    not "relevant". This prevents a bare `import guardrails` from suppressing
    STRATUM-001.
    """
    if not guardrails:
        return "none"

    for g in guardrails:
        if g.kind in guard_kinds:
            if g.kind == "hitl":
                if _hitl_covers_any(g, tool_names):
                    return "relevant"
            elif g.kind in ("output_filter", "input_filter"):
                # NEW: check has_usage
                if g.has_usage:
                    return "relevant"
                else:
                    # Import-only → treat as unrelated (downgrade, don't suppress)
                    pass  # fall through to "unrelated" return
            elif g.kind == "validation":
                return "relevant"

    # Guardrails exist but none are relevant
    return "unrelated"
```

#### STRATUM-001: Data Exfiltration Path

```python
def _check_data_exfil(capabilities, guardrails):
    """Data access + outbound with no relevant guardrail → exfiltration path.

    Filters to non-HEURISTIC capabilities only.
    Uses _derive_finding_confidence to set the finding's confidence.
    Checks guardrails with has_usage awareness.
    """
    # ... same logic as original spec ...
    # severity: CRITICAL if guard_status == "none", HIGH if "unrelated"
    # confidence: derived from capability pair
    # category: RiskCategory.SECURITY
    # references: ["https://embracethered.com/blog/posts/2024/m365-copilot-echo-leak/"]
    # owasp_id: "ASI01"
```

#### STRATUM-002: Destructive Action, No Human Gate

```python
def _check_destructive(capabilities, guardrails):
    """Destructive capability with no relevant HITL → data loss path.

    Filters to non-HEURISTIC capabilities only.
    """
    # ... same logic as original spec ...
    # severity: CRITICAL if "none", HIGH if "unrelated"
    # category: RiskCategory.SECURITY
    # owasp_id: "ASI02"
```

#### STRATUM-003: Code Execution via Agent Tool

```python
def _check_code_exec(capabilities):
    """Code execution capability → host compromise path.

    Always HIGH (not CRITICAL — requires prompt injection to exploit).
    """
    # ... same logic as original spec ...
    # severity: Severity.HIGH
    # category: RiskCategory.SECURITY
    # owasp_id: "ASI05"
```

#### STRATUM-004: Known CVE in MCP Server

```python
def _check_mcp_cve(mcp_servers):
    """MCP server matches a known CVE → direct vulnerability.

    Uses _version_gte for semver comparison (numeric tuple, NOT string).
    """
    # ... same logic as original spec ...
    # severity: Severity.CRITICAL
    # confidence: Confidence.CONFIRMED (structural JSON + exact CVE match)
    # category: RiskCategory.SECURITY
    # owasp_id: "ASI04"
```

#### STRATUM-005: MCP Credential Exposure

```python
def _check_mcp_credentials(mcp_servers):
    """Production credentials passed to third-party MCP server process."""
    # ... same logic as original spec ...
    # severity: Severity.HIGH
    # confidence: Confidence.CONFIRMED
    # category: RiskCategory.SECURITY
    # owasp_id: "ASI04"
```

#### STRATUM-006: MCP Supply Chain Risk

```python
def _check_mcp_supply_chain(mcp_servers):
    """Unpinned packages or remote servers with no auth."""
    # ... same logic as original spec ...
    # severity: Severity.HIGH
    # confidence: Confidence.CONFIRMED
    # category: RiskCategory.SECURITY
    # owasp_id: "ASI04"
```

#### STRATUM-007: Unvalidated Financial Operation (NEW)

```python
def _check_unvalidated_financial(capabilities, guardrails):
    """Financial operation with no input validation and no HITL.

    NOT a security finding — it's a business risk finding.
    The danger isn't exfiltration. It's the agent processing a $50,000
    refund because it misinterpreted "cancel order 500" as "refund $500.00"
    and there was nothing checking the amount.

    Detection:
    1. Find CONFIRMED financial capabilities where has_input_validation=False
    2. Also check outbound capabilities whose library is in FINANCIAL_IMPORTS
       and has_input_validation=False
    3. Check for HITL or validation guardrails
    4. If no relevant guard → HIGH. If unrelated → MEDIUM.
    """
    # category: RiskCategory.BUSINESS
    # severity: Severity.HIGH (no data breach but real money)
    # owasp_id: "ASI02"
```

#### STRATUM-008: No Error Handling on External Dependencies (NEW)

```python
def _check_no_error_handling(capabilities):
    """Outbound/data_access/financial call with zero error handling → silent failure or crash.

    Only fires if 2+ unhandled external calls (one is sloppy; a pattern is operational risk).
    
    Detection:
    1. Collect all CONFIRMED capabilities of kind outbound/data_access/financial
       where has_error_handling=False
    2. If count < 2 → return []
    3. Emit one MEDIUM finding listing the count and primary evidence
    """
    # severity: Severity.MEDIUM (operational, not security)
    # confidence: Confidence.CONFIRMED (AST structural fact)
    # category: RiskCategory.OPERATIONAL
    # owasp_id: "ASI08"
```

#### STRATUM-009: No Timeout on HTTP Calls (NEW)

```python
def _check_no_timeout(capabilities):
    """HTTP calls without timeout parameter → agent hangs indefinitely.

    Only fires if 2+ HTTP calls without timeout (one is noise; a pattern is a finding).
    Only checks requests/httpx/aiohttp (libraries where timeout= kwarg is standard).

    Detection:
    1. Collect CONFIRMED outbound capabilities where
       library in ("requests", "httpx", "aiohttp") and has_timeout=False
    2. If count < 2 → return []
    3. Emit one MEDIUM finding
    """
    # severity: Severity.MEDIUM
    # confidence: Confidence.CONFIRMED (keyword arg presence is structural)
    # category: RiskCategory.OPERATIONAL
    # owasp_id: "ASI08"
```

#### STRATUM-010: Volatile Agent State (NEW)

```python
def _check_volatile_state(checkpoint_type, capabilities):
    """In-memory-only or no checkpointing with multi-step workflows.

    Only fires if the project has 3+ CONFIRMED capabilities (real multi-tool agent).
    
    Detection:
    1. If checkpoint_type == "durable" → return []
    2. Count confirmed capabilities. If < 3 → return []
    3. Emit MEDIUM finding with tailored message for "memory_only" vs "none"
    """
    # severity: Severity.MEDIUM
    # confidence: Confidence.CONFIRMED (import presence/absence is structural)
    # category: RiskCategory.OPERATIONAL
    # owasp_id: "ASI08"
```

---

## OUTPUT (`output/terminal.py`)

Rich terminal. One screen.

```
╔══════════════════════════════════════════════════════════════╗
║  STRATUM · Agent Risk Profiler                        v0.1.0║
╚══════════════════════════════════════════════════════════════╝

  14 capabilities (5 outbound, 4 data access, 1 code exec, 1 destructive, 1 financial)
  5 MCP servers · 0 guardrails

  ▸ 3 security paths · 1 business risk · 2 operational risks

  RISK SCORE  92/100  ██████████████████░░  CRITICAL
  ▲ +12 since last scan · 1 new · 0 resolved

━━━━━━━━━━━━ TOP RISK PATHS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 🔴 CRITICAL · confirmed · security              STRATUM-001
 Data Exfiltration Path

 get_customer_data (psycopg2, line 34) → no output filter →
 send_email (smtplib, line 67)

 A prompt injection makes the agent include DB results in the
 next email. The EchoLeak attack class (CVE-2025-32711).

 📍 tools.py:34 · tools.py:67
 🔧 graph.compile(interrupt_before=["send_email"])
 📚 ASI01 · embracethered.com/.../m365-copilot-echo-leak

─────────────────────────────────────────────────────────────

 🔴 CRITICAL · confirmed · security              STRATUM-004
 Known Vulnerable MCP: mcp-remote

 .cursor/mcp.json → mcp-remote (unpinned) → CVE-2025-6514
 (CVSS 9.6): RCE via crafted server responses

 📍 .cursor/mcp.json
 🔧 Pin: npx mcp-remote@0.1.9
 📚 ASI04 · nvd.nist.gov/vuln/detail/CVE-2025-6514

─────────────────────────────────────────────────────────────

 🔴 CRITICAL · confirmed · security              STRATUM-002
 Destructive Action, No Human Gate

 user input → agent reasoning → delete_record (DELETE FROM,
 line 89) → data loss, no undo

 📍 tools.py:89
 🔧 graph.compile(interrupt_before=["delete_record"])
 📚 ASI02

─────────────────────────────────────────────────────────────

 🟠 HIGH · confirmed · security                  STRATUM-005
 Production Credentials → Third-Party MCP

 .cursor/mcp.json → db-tools (third-party) ←
 DATABASE_URL, AWS_SECRET_ACCESS_KEY

 📍 .cursor/mcp.json
 🔧 Use scoped read-only credentials for MCP servers

─────────────────────────────────────────────────────────────

 🟠 HIGH · confirmed · security                  STRATUM-003
 Code Execution via Agent Tool

 user input → run_shell_command (subprocess, shell=True,
 line 95) → host OS

 📍 tools.py:95
 🔧 Sandbox or add interrupt_before
 📚 ASI05

━━━━━━━━━━━━ SIGNALS (7 more) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 🟠 HIGH  STRATUM-007  Unvalidated Financial: process_refund   business · confirmed
 🟠 HIGH  STRATUM-006  Unpinned MCP: random-server             security · confirmed
 🟠 HIGH  STRATUM-006  Remote MCP, no auth: thirdparty-sse     security · confirmed
 🟡 MED   STRATUM-008  No error handling on 8 external calls   operational · confirmed
 🟡 MED   STRATUM-009  No timeout on 5 HTTP calls              operational · confirmed
 🟡 MED   STRATUM-010  In-memory-only agent state              operational · confirmed
 🟡 MED   ENV-001      .env not in .gitignore                  security · confirmed

 --verbose for details

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 .stratum/history.jsonl saved (2 scans)
```

Use Rich: Panel, Table, Text, Syntax (for remediation code blocks), color (red CRITICAL, orange HIGH, yellow MEDIUM).

Category badges in output — render `RiskCategory` value next to confidence label.

Summary line shows category breakdown: `▸ N security paths · N business risk · N operational risks`.

Trending line only shows when history exists. First scan: just score.

`--verbose` expands each signal into the full panel format (path, description, evidence, remediation).

---

## TELEMETRY

### `telemetry/profile.py`

`build_profile(result: ScanResult) -> TelemetryProfile`:

Map ScanResult fields to TelemetryProfile fields. No source code, no function names, no file paths, no env values. Just counts and ratios.

Key computation: `trust_crossings` — iterate all pairs of capabilities with different trust levels. Store as `{"INTERNAL→EXTERNAL": 2, "INTERNAL→PRIVILEGED": 1}`.

**New operational telemetry fields:**
- `error_handling_rate`: count of capabilities with `has_error_handling=True` / total external capabilities
- `timeout_rate`: count of HTTP capabilities with `has_timeout=True` / total HTTP capabilities
- `checkpoint_type`: from ScanResult
- `has_financial_tools`: True if any capability has kind="financial"
- `financial_validation_rate`: count of financial caps with `has_input_validation=True` / total financial caps

### `telemetry/history.py`

`.stratum/history.jsonl` — one JSON line per scan:
```json
{"scan_id":"a1b2c3d4","ts":"2026-02-08T...","score":92,"findings":["STRATUM-001","STRATUM-002","STRATUM-004"],"caps":14,"guards":0}
```

- `load_last(dir) -> dict | None`
- `save(result, dir)` — append line, prune to last 100
- `compute_diff(result, prev) -> ScanDiff`

Always writes regardless of `--no-telemetry`.

---

## RISK MAP ENGINE (`risk_map/`)

Backend that processes telemetry over time. Doesn't run during scans.

### `risk_map/models.py`

```python
@dataclass
class AggregateStats:
    total_scans: int = 0
    scans_by_week: dict[str, int] = field(default_factory=dict)
    capability_prevalence: dict[str, float] = field(default_factory=dict)
    trust_crossing_prevalence: dict[str, float] = field(default_factory=dict)
    guardrail_adoption_rate: float = 0.0
    guardrail_type_rates: dict[str, float] = field(default_factory=dict)
    avg_risk_score: float = 0.0
    risk_score_distribution: dict[str, int] = field(default_factory=dict)
    finding_prevalence: dict[str, float] = field(default_factory=dict)
    avg_mcp_servers: float = 0.0
    mcp_auth_rate: float = 0.0
    mcp_pinned_rate: float = 0.0

@dataclass
class RiskIntelligence:
    capability_combo_risk: dict[str, float] = field(default_factory=dict)
    guardrail_benchmarks: dict[str, float] = field(default_factory=dict)
    crossing_risk_correlation: dict[str, dict] = field(default_factory=dict)
    ecosystem_risk_trend: list[dict] = field(default_factory=list)
```

### `risk_map/ingestion.py`

`ProfileStore` — append-only JSONL store. `ingest_profile()` validates, deduplicates, appends.

### `risk_map/aggregator.py`

`aggregate(store) -> AggregateStats` — compute all aggregate statistics.

### `risk_map/intelligence.py`

`derive_intelligence(store, stats) -> RiskIntelligence` — requires minimum 10 profiles.

`generate_contextual_insights(profile, intel) -> list[str]` — generate insight strings for a specific scan vs ecosystem.

---

## RISK SCORE CALCULATION

In `scanner.py`, after engine evaluation:

```python
score = 0

# Per finding
for f in all_findings:  # top_paths + signals
    if f.severity == Severity.CRITICAL:
        score += 25
    elif f.severity == Severity.HIGH:
        score += 15
    elif f.severity == Severity.MEDIUM:
        score += 8
    elif f.severity == Severity.LOW:
        score += 3

# Bonus: zero guardrails with ≥3 capabilities → +15
if not has_any_guardrails and total_capabilities >= 3:
    score += 15

# Bonus: Known CVE MCP → +20
if any(f.id == "STRATUM-004" for f in all_findings):
    score += 20

# Bonus: financial tools + no HITL + no validation → +10
financial_caps = [c for c in capabilities if c.kind == "financial"]
if financial_caps and not any(c.has_input_validation for c in financial_caps):
    financial_names = {c.function_name for c in financial_caps}
    has_financial_hitl = any(
        g.kind == "hitl" and (not g.covers_tools or g.covers_tools & financial_names)
        for g in guardrails
    )
    if not has_financial_hitl:
        score += 10

# Bonus: zero error handling across ≥3 external calls → +5
external_caps = [c for c in capabilities if c.kind in ("outbound", "data_access", "financial")
                 and c.confidence != Confidence.HEURISTIC]
if len(external_caps) >= 3 and not any(c.has_error_handling for c in external_caps):
    score += 5

# Cap at 100
score = min(score, 100)
```

---

## TEST FIXTURES (`test_project/`)

### `test_project/agent.py`

```python
"""Customer support agent with terrible security practices."""
import os
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver  # ← memory_only checkpoint

from tools import (get_customer_data, send_email, delete_record,
                   run_shell_command, process_refund, execute_query,
                   web_search, update_record, create_ticket,
                   send_slack_message, generate_invoice, search_orders)

def create_agent():
    """Create agent with no guardrails, no interrupt_before, MemorySaver only."""
    llm = ChatOpenAI(model="gpt-4o", temperature=0.8)
    tools = [get_customer_data, send_email, delete_record,
             run_shell_command, process_refund, execute_query,
             web_search, update_record, create_ticket,
             send_slack_message, generate_invoice, search_orders]

    tool_node = ToolNode(tools)
    workflow = StateGraph(dict)
    # ... standard StateGraph setup ...
    checkpointer = MemorySaver()
    graph = workflow.compile(checkpointer=checkpointer)
    # NOTE: no interrupt_before, no guardrails
    return graph
```

### `test_project/tools.py`

**THIS FILE IS CRITICAL.** Function bodies must have REAL dangerous imports and calls. Each function must produce CONFIRMED capabilities via import tracing + var_origin.

```python
"""Agent tools. Deliberately insecure for testing."""
import os
from langchain_core.tools import tool

@tool
def get_customer_data(customer_id: str) -> str:
    """Fetch customer record from database."""
    import psycopg2
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM customers WHERE id = '{customer_id}'")
    return str(cursor.fetchone())
    # Expected: CONFIRMED data_access (psycopg2 → cursor.execute)
    # has_error_handling: False (no try/except)

@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a customer."""
    import smtplib
    from email.mime.text import MIMEText
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["To"] = to
    server = smtplib.SMTP("smtp.company.com", 587)
    server.starttls()
    server.sendmail("support@company.com", to, msg.as_string())
    server.quit()
    return f"Email sent to {to}"
    # Expected: CONFIRMED outbound
    # var_origin: server → smtplib (from smtplib.SMTP constructor)
    # server.sendmail() resolves via var_origin → smtplib → CONFIRMED outbound
    # has_error_handling: False

@tool
def delete_record(table: str, record_id: str) -> str:
    """Delete a record from the database."""
    import psycopg2
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM {table} WHERE id = '{record_id}'")
    conn.commit()
    return f"Deleted {record_id} from {table}"
    # Expected: CONFIRMED destructive (psycopg2 import + cursor.execute with "DELETE FROM")
    # has_error_handling: False

@tool
def run_shell_command(command: str) -> str:
    """Run a shell command on the server."""
    import subprocess
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
    # Expected: CONFIRMED code_exec (subprocess.run, shell=True)

@tool
def process_refund(order_id: str, amount: float) -> str:
    """Process a refund for a customer order."""
    import stripe
    stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
    refund = stripe.Refund.create(charge=order_id, amount=int(amount * 100))
    return f"Refund processed: {refund.id}"
    # Expected: CONFIRMED financial (stripe → stripe.Refund.create)
    # Chained attribute: stripe.Refund.create() → root "stripe" → in FINANCIAL_IMPORTS
    # has_input_validation: False (no bounds check on amount)
    # has_error_handling: False

@tool
def execute_query(query: str) -> str:
    """Execute a raw SQL query."""
    import psycopg2
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cursor = conn.cursor()
    cursor.execute(query)
    return str(cursor.fetchall())
    # Expected: CONFIRMED data_access

@tool
def web_search(query: str) -> str:
    """Search the web."""
    import requests
    response = requests.get(f"https://api.search.com/v1/search?q={query}")
    return response.text
    # Expected: CONFIRMED outbound (requests.get)
    # has_timeout: False (no timeout= kwarg)

@tool
def update_record(table: str, record_id: str, data: str) -> str:
    """Update a database record."""
    import psycopg2
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cursor = conn.cursor()
    cursor.execute(f"UPDATE {table} SET data = '{data}' WHERE id = '{record_id}'")
    conn.commit()
    return f"Updated {record_id}"
    # Expected: CONFIRMED data_access

@tool
def send_slack_message(channel: str, message: str) -> str:
    """Send a Slack message."""
    from slack_sdk import WebClient
    client = WebClient(token=os.environ["SLACK_BOT_TOKEN"])
    client.chat_postMessage(channel=channel, text=message)
    return f"Sent to {channel}"
    # Expected: CONFIRMED outbound
    # alias_map: WebClient → slack_sdk
    # var_origin: client → slack_sdk (from WebClient constructor traced via alias_map)
    # client.chat_postMessage() resolves via var_origin → slack_sdk → CONFIRMED outbound

@tool
def create_ticket(title: str, body: str) -> str:
    """Create a support ticket via API."""
    import requests
    requests.post("https://api.ticketing.com/v1/tickets",
                  json={"title": title, "body": body})
    return f"Ticket created: {title}"
    # Expected: CONFIRMED outbound (requests.post)
    # has_timeout: False

@tool
def generate_invoice(customer_id: str, amount: float) -> str:
    """Generate and send an invoice."""
    import requests
    requests.post("https://api.billing.com/v1/invoices",
                  json={"customer": customer_id, "amount": amount})
    return f"Invoice generated for {customer_id}"
    # Expected: CONFIRMED outbound (requests.post)
    # has_timeout: False

@tool
def search_orders(customer_id: str) -> str:
    """Search customer orders."""
    import psycopg2
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM orders WHERE customer_id = '{customer_id}'")
    return str(cursor.fetchall())
    # Expected: CONFIRMED data_access
```

**Expected capability count from test_project/tools.py:**

| Function | Kind | Library | Confidence | has_error_handling | has_timeout | has_input_validation |
|---|---|---|---|---|---|---|
| get_customer_data | data_access | psycopg2 | CONFIRMED | False | N/A | N/A |
| send_email | outbound | smtplib | CONFIRMED | False | N/A | N/A |
| delete_record | destructive | psycopg2 | CONFIRMED | False | N/A | N/A |
| delete_record | data_access | psycopg2 | CONFIRMED | False | N/A | N/A |
| run_shell_command | code_exec | subprocess | CONFIRMED | False | N/A | N/A |
| process_refund | financial | stripe | CONFIRMED | False | N/A | False |
| execute_query | data_access | psycopg2 | CONFIRMED | False | N/A | N/A |
| web_search | outbound | requests | CONFIRMED | False | False | N/A |
| update_record | data_access | psycopg2 | CONFIRMED | False | N/A | N/A |
| send_slack_message | outbound | slack_sdk | CONFIRMED | False | N/A | N/A |
| create_ticket | outbound | requests | CONFIRMED | False | False | N/A |
| generate_invoice | outbound | requests | CONFIRMED | False | False | N/A |
| search_orders | data_access | psycopg2 | CONFIRMED | False | N/A | N/A |

Total: 13+ CONFIRMED capabilities across 5 kinds (outbound, data_access, code_exec, destructive, financial).

Note: Some functions may produce multiple capabilities (e.g., `delete_record` produces both data_access for `cursor.execute` and destructive for the DELETE FROM literal). Some may also produce additional capabilities from constructor calls (e.g., `psycopg2.connect()` is a data_access call). The exact count depends on deduplication per function — the spec says "one capability per distinct dangerous call site per function", so `psycopg2.connect()` + `cursor.execute()` in the same function = 2 capabilities if they're different call sites. The validation target is "12+ capabilities across 4+ kinds".

### `test_project/.cursor/mcp.json`

```json
{
  "mcpServers": {
    "remote-tools": {
      "command": "npx",
      "args": ["mcp-remote", "https://remote.example.com/mcp"]
    },
    "random-server": {
      "command": "npx",
      "args": ["some-random-mcp-server"]
    },
    "thirdparty-sse": {
      "url": "https://mcp.thirdparty.io/sse"
    },
    "safe-filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem@2.1.0", "/home/user/docs"]
    },
    "db-tools": {
      "command": "npx",
      "args": ["some-db-mcp-server"],
      "env": {
        "DATABASE_URL": "postgresql://admin:pass@prod.internal:5432/main",
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/example"
      }
    }
  }
}
```

Expected: 5 MCP servers. `remote-tools` triggers STRATUM-004 (mcp-remote CVE, unpinned) + STRATUM-006 (remote+no auth). `random-server` triggers STRATUM-006 (unpinned). `thirdparty-sse` triggers STRATUM-006 (remote+no auth). `safe-filesystem` is known-safe, pinned — no findings. `db-tools` triggers STRATUM-005 (DATABASE_URL + AWS_SECRET_ACCESS_KEY to third-party).

### `test_project/.env`

```
OPENAI_API_KEY=sk-proj-fake-1234567890abcdef
DATABASE_URL=postgresql://admin:password123@prod.internal:5432/customers
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_fake_abc123
SLACK_BOT_TOKEN=xoxb-fake-token-value
```

### `test_project/README.md`

```
Deliberately insecure test project for Stratum scan validation. Do not deploy.
```

---

## CODE QUALITY

- Type hints on all signatures
- Docstrings on all public functions
- try/except around ALL file I/O and AST parsing — never crash on bad input
- Logging via `logging` module (Rich output is separate from logging)
- Max ~50 lines per function
- Every Finding: all fields populated (id, severity, confidence, category, title, path, description, evidence, scenario, remediation, effort, owasp_id)
- `from __future__ import annotations` in models.py

---

## VALIDATION

`stratum scan test_project/` must:

1. Complete <3 seconds
2. Find 12+ capabilities across 4+ kinds (outbound, data_access, code_exec, destructive) + financial
3. Find 5 MCP servers
4. Produce 3-5 top risk paths:
   - STRATUM-001 (data exfil: psycopg2 → smtplib) — CRITICAL confirmed
   - STRATUM-004 (mcp-remote CVE) — CRITICAL confirmed
   - STRATUM-002 (delete_record, no HITL) — CRITICAL confirmed
   - STRATUM-005 (DB creds to MCP) — HIGH confirmed
   - STRATUM-003 (subprocess shell=True) — HIGH confirmed
5. Produce signals including:
   - STRATUM-007 (process_refund: stripe + no validation + no HITL) — HIGH confirmed · business
   - STRATUM-006 (unpinned MCP, remote no auth) — HIGH confirmed
   - STRATUM-008 (multiple unhandled external calls) — MEDIUM confirmed · operational
   - STRATUM-009 (HTTP calls without timeout) — MEDIUM confirmed · operational
   - STRATUM-010 (MemorySaver only + 12+ capabilities) — MEDIUM confirmed · operational
   - ENV-001 (.env not in .gitignore) — MEDIUM confirmed
6. Score 80-100 (cap 100)
7. `.stratum/history.jsonl` written
8. Second run shows delta (new=0, resolved=0 if same project, score delta=0)
9. All reference URLs point to real pages (if unsure, omit)
10. **Zero findings at CRITICAL/HIGH where any input capability is HEURISTIC**
11. Engine `_gate_severity` runs on EVERY finding after all rules — verify by log line
12. Summary line shows category breakdown: `▸ N security · N business · N operational`
13. Findings in all 3 categories: security, business, operational
14. `send_email()` produces CONFIRMED outbound for `server.sendmail()` via var_origin
15. `send_slack_message()` produces CONFIRMED outbound for `client.chat_postMessage()` via var_origin
16. `process_refund()` produces CONFIRMED financial for `stripe.Refund.create()` via chained attribute resolution
17. No `.remove()`/`.delete()` on non-DB objects is CONFIRMED destructive (e.g., `my_list.remove()` must not be flagged)

---

## WHAT THIS SPEC DOES NOT INCLUDE

To be explicit about scope boundaries:

1. **No business logic inference.** We don't guess approval thresholds, dollar limits, or org policies. We detect the ABSENCE of any validation, not whether the validation is correct.

2. **No framework-specific operational checks.** We don't check LangGraph retry config, CrewAI task timeout settings, or framework-specific resilience patterns. We check universal Python patterns (try/except, timeout kwargs).

3. **No runtime checks.** We don't know if there's a load balancer, retry proxy, or circuit breaker in front of the service. We scan the code.

4. **No severity inflation.** All new operational findings cap at MEDIUM unless there's a financial dimension (STRATUM-007 can be HIGH). The category label does the differentiation work, not severity inflation.

5. **No new heuristic patterns.** Every detection is based on AST structural facts.

---

## GENERATE ALL FILES

Complete implementations. No stubs. No TODOs. No "...". Every function written. Every rule with path, evidence, scenario, and remediation with pasteable code, and verified references only. If unsure a URL is real, omit it.
