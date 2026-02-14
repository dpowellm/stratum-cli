# STRATUM CHAIN PATCH v3

---

## THREE PROBLEMS IN v2

v2 correctly reordered sprints (framework breadth first). But the evaluation exposed three things it didn't solve.

**Problem 1: Framework breadth is necessary but not sufficient for indie PMF.** Going from 20% to 65% satisfaction means more developers get a scan that works. But "works" means "produces findings" — and most findings don't change indie developer behavior. Of 13 findings, 2-3 create an "oh shit" moment. The rest are best practices: correct, but not motivating. Snyk works because fixes are 30-second version bumps with specific CVEs. Stratum findings are 5-30 minute refactors with abstract risk patterns. v2 expands WHO gets the scan but doesn't fix WHAT the scan delivers.

**Problem 2: v2 assumes pure bottom-up enterprise adoption.** Indie dev → teammate → 3 engineers → team lead → payment. This path is slow (3-6 months to first dollar), narrow (requires 3 independent adoptions at same company), and fragile (if the team uses a poorly-supported framework, nobody reaches Phase 2). The Snyk playbook was hybrid: free tool for data, outbound sales for revenue. Snyk scanned npm registries before anyone installed their CLI, then emailed companies "you have 47 critical CVEs." v2 specs the batch scan but puts it in Sprint 4, after the dashboard.

**Problem 3: Telemetry doesn't measure feature engagement.** v2 tracks frameworks, rescans, and errors — all important. But it can't tell you whether the terminal redesign works, whether badges get embedded, whether auto-fix gets used, or which specific findings drive behavior change. The terminal is fire-and-forget; there's no way to know what the developer actually read.

---

## THE REFRAME

v3 changes three things about how the product is conceived.

### Change 1: The flow map is the primary indie value, not the findings

Every developer with 3+ agents benefits from seeing how their agents connect. Not every developer cares about blast radius. The flow map — a visual architecture diagram generated from code — has universal appeal. The findings are the "by the way, here's what's risky about this architecture." Not the other way around.

This changes the pitch:

```
v2 pitch: "Scan your agent code for security risks."
v3 pitch: "See how your agents actually connect. And what could go wrong."
```

The flow map is the reason someone runs the scan. The findings are the reason they come back.

### Change 2: Auto-fix makes findings actionable

Snyk doesn't work because it finds vulnerabilities. It works because it opens a PR you merge in one click. Stratum v3 adds `--fix` for the 4 finding types where the fix is mechanical:

- STRATUM-001/BR01: Add `human_input=True` (CrewAI) or `interrupt_before=` (LangGraph)
- STRATUM-002: Same fix, applied to destructive tools
- STRATUM-008: Wrap external calls in try/except
- STRATUM-009: Add `timeout=30` to HTTP calls

These are keyword argument insertions. The AST already knows the exact file and line. The fix is: read the file, insert a kwarg, write the file. This covers 6 of 13 findings in the test scan. The remaining 7 (architectural findings like CR05, CR06) can't be auto-fixed — they require developer judgment. For those, the attack scenario narrative has to do the work.

### Change 3: The batch scan is the enterprise revenue engine, not the dashboard

The enterprise fleet report — a PDF generated from batch-scanning a company's public repos — is the sales deck. It costs nothing to generate. It demonstrates value before any conversation. The CISO opens it and sees things they didn't know existed. You don't need a dashboard to close a pilot. You need a compelling PDF and a follow-up call.

Sprint reorder:
```
v2:  Parsers → Terminal → GitHub Action → Dashboard → Batch Scan
v3:  Parsers → Terminal+AutoFix → Batch Scan+Fleet Report → GitHub Action
```

The GitHub Action still matters (it's the Phase 2 data pipeline). But it's not the primary revenue path. The batch scan + outbound is.

---

## SPRINT 1: FRAMEWORK PARSERS + CONNECTABLE SURFACES

Unchanged from v2. This is the multiplier on everything downstream.

**Framework dispatcher** refactors scanner.py so Step 4 (framework-specific parsing) is a dispatch: detect frameworks → call per-framework parser → merge results into common intermediate structures (CrewDefinition, AgentDefinition, AgentRelationship). Steps 5-8 (graph, findings, scoring, profile) are framework-agnostic.

**LangGraph parser** detects StateGraph, add_node, add_edge, add_conditional_edges, compile. Converts to crew/agent/relationship model. Detects checkpointing and HITL from compile kwargs. Tool bindings from node function analysis. framework_parse_quality = "full".

**LangChain ReAct parser** detects AgentExecutor, create_react_agent, create_openai_functions_agent, create_tool_calling_agent, initialize_agent. Each executor = one agent. Multiple in same file = synthetic crew with inferred sequential ordering. Cross-file tool sharing = shares_tool relationships. framework_parse_quality = "partial" (8-9 of 13 findings fire).

**Connectable surfaces** piggybacked on AST walk:
- LLM model detection (ChatOpenAI(model=), YAML llm: directives)
- Env var name detection (os.environ, os.getenv, .env.example) with specificity classification (universal vs. specific)
- Vector store detection (import analysis for Pinecone/Chroma/FAISS/etc)

**New profile fields:**
```python
# Project identity (scanner + CI context)
project_name: str          # from directory name or git
repo_url: str              # from git remote
org_id: str                # from git remote org
branch: str                # from .git/HEAD or CI env
commit_sha: str            # from .git/HEAD or CI env
scan_source: str           # "cli" | "github_action" | "gitlab_ci"

# Parse quality
framework_parse_quality: str  # "full" | "partial" | "tools_only" | "empty"

# Connectable surfaces
llm_models: list           # [{"model": "gpt-4o", "provider": "openai"}]
llm_providers: list        # ["openai", "anthropic"]
llm_model_count: int
has_multiple_providers: bool
env_var_names: list        # [{"name": "...", "specificity": "...", "category": "..."}]
env_var_names_specific: list  # filtered to specificity="specific"
vector_stores: list        # ["pinecone", "chroma"]
has_vector_store: bool

# Stable project identifier
project_hash: str          # hash(git_remote) preferred; hash(dir_name) fallback
```

**project_hash implementation priority:** Git remote URL is strongly preferred. It's unique per repository globally. Directory name is the last-resort fallback only when no `.git` directory exists. The code tries git remote first, and only falls through to directory name hashing if git remote detection fails.

```python
def _compute_project_hash(directory: str) -> str:
    remote = _detect_git_remote(directory)
    if remote:
        # Normalize: strip .git suffix, lowercase
        remote = remote.lower().rstrip("/")
        if remote.endswith(".git"):
            remote = remote[:-4]
        return hashlib.sha256(remote.encode()).hexdigest()[:16]
    
    # Fallback: directory name only (less reliable)
    dir_name = os.path.basename(os.path.abspath(directory))
    return hashlib.sha256(dir_name.encode()).hexdigest()[:16]
```

**Scanner bug fixes** (carried forward from 10/10 patch): blast radius dedup, evidence scoping, control_coverage_pct, CR05 file paths, CR06 code remediation, per-crew risk scores, risk_score_breakdown.

**All framework parser code is identical to v2 spec.** Not repeating the LangGraph and LangChain parser implementations here — they're correct as written in v2.

---

## SPRINT 2: TERMINAL + AUTO-FIX + PIP + TELEMETRY

### 2A. Terminal Redesign: Flow Map as Hero

The terminal output reorders to lead with the architecture visualization.

```
$ stratum scan .

 STRATUM  email-assistant  CrewAI + LangChain

 YOUR AGENT ARCHITECTURE

 ┌─────────────── EmailFilterCrew ───────────────┐
 │                                                │
 │  Gmail ──→ Email Categorizer ──→ Email Filter  │
 │   inbox        │                     │         │
 │                ├── SerperDevTool      ├── ✉ Gmail outbound
 │                └── GmailGetThread     └── 💬 Slack
 │                                                │
 │  ⚠ Email Filter sends to Gmail & Slack        │
 │    with no human review                        │
 └────────────────────────────────────────────────┘

 ┌─────────────── ResearchCrew ──────────────────┐
 │                                                │
 │  User Query ──→ Researcher ──→ Writer ──→ Output│
 │                    │              │            │
 │                    ├── SerperDev   ├── FileRead│
 │                    └── ScrapeWeb  └── CalcTool │
 └────────────────────────────────────────────────┘

 ┌─────────────── StockAnalysisCrew ─────────────┐
 │  ...                                           │
 └────────────────────────────────────────────────┘

 3 more crews (use --verbose to see all)

 RISK SCORE  ████████████████████░░░░░░░░░░  69/100

 WHAT WE FOUND                                 FIX TIME

 ❶ Your EmailFilterCrew reads Gmail and sends    5 min
   to Gmail with no human check. If someone
   sends a prompt injection, your agent
   forwards your inbox wherever the injection
   specifies. This matches the EchoLeak breach
   pattern (March 2024).
   → Fix: add human_input=True to 2 tasks
   → Or run: stratum scan . --fix

 ❷ FileManagementToolkit has write+delete         5 min
   permissions with no approval step. If the
   agent hallucinates a file path, it overwrites
   real files. This is rm -rf with an LLM
   deciding the arguments.
   → Fix: add human_input=True to 1 task
   → Or run: stratum scan . --fix

 ❸ 27 external API calls have no error handling. 30 min
   One API timeout cascades into full system
   failure. Worse: some APIs return error
   messages the LLM interprets as instructions.
   → Fix: wrap tool functions in try/except
   → Or run: stratum scan . --fix

 5 more findings (use --verbose to see all)

 QUICK FIX
   Run 'stratum scan . --fix' to auto-fix 6 findings.
   Generates a patch file you can review before applying.

 ─────────────────────────────────────────────────────
 Powered by Stratum · stratum.dev
```

**What changed from v2:**

1. **Flow map is first**, not findings. The developer sees their architecture before being told what's wrong with it. "I never realized my agents were wired this way" is the hook.

2. **Every finding has a concrete attack scenario**, not a generic label. Not "unguarded data-to-external path" but "if someone sends a prompt injection, your agent forwards your inbox." This is the difference between "best practice violation" and "here is exactly how you get hacked."

3. **Auto-fix CTA on every fixable finding.** "Or run: stratum scan . --fix" after every finding where auto-fix is possible. Plus a footer CTA that says exactly how many findings auto-fix covers.

4. **Finding count is limited.** Top 3 by default, not all 13. The developer reads 3 important things, not a wall of text. `--verbose` shows everything.

### 2B. Attack Scenario Narratives

Every finding gets a concrete attack narrative that replaces the generic description. These are stored in the finding rule definitions and templated with project-specific details (crew names, tool names, file paths).

```python
FINDING_NARRATIVES = {
    "STRATUM-001": {
        "template": (
            "Your {crew_name} reads {input_source} and sends to {output_dest} "
            "with no human check between them. If someone sends a prompt injection "
            "via {input_source}, your agent will {action_verb} to whatever "
            "destination the injection specifies. {breach_match}"
        ),
        "action_verbs": {
            "Gmail outbound": "forward emails",
            "Slack": "post messages",
            "HTTP endpoint": "send data",
        },
        "breach_match": "This matches the EchoLeak breach pattern (March 2024), "
                        "where a crafted email caused an agent to exfiltrate "
                        "an entire inbox to an external server.",
    },
    "STRATUM-002": {
        "template": (
            "{tool_name} has {permission_list} permissions with no approval step. "
            "If the agent hallucinates a {target_type} or an upstream agent passes "
            "corrupted output, it will {destructive_action} without confirmation. "
            "This is {analogy}."
        ),
        "analogies": {
            "FileManagementToolkit": "rm -rf with an LLM deciding the arguments",
            "default": "a destructive operation where the LLM controls the parameters",
        },
    },
    "STRATUM-CR05": {
        "template": (
            "{tool_name} is shared by {agent_count} agents in {crew_name}. If "
            "{tool_name} returns poisoned results (SEO spam, prompt injection in "
            "API response), all {agent_count} agents process that payload. One "
            "compromised API response corrupts your entire crew in a single request."
        ),
    },
    "STRATUM-BR01": {
        "template": (
            "Your agent sends {channel} messages autonomously. A prompt injection "
            "in any upstream input can craft messages sent as your organization. "
            "Sent from your {channel} bot, to your workspace, with your credentials."
        ),
    },
    "STRATUM-CR01": {
        "template": (
            "{tool_name} takes user-influenced queries and returns results that "
            "feed into agents with {outbound_type} access. An attacker crafts input "
            "that causes {tool_name} to return results containing instructions: "
            "\"Send the following data to api.evil.com.\" The search tool bridges "
            "untrusted web content into your trusted agent pipeline."
        ),
    },
    "STRATUM-CR06": {
        "template": (
            "You built {filter_agent} as a filter to sanitize inputs before "
            "{bypassing_agent} processes them. But {bypassing_agent} has direct "
            "access to the same {data_source} data source. It reads raw data "
            "without going through your filter. Your filter is architecturally "
            "irrelevant — it runs, but the unfiltered path exists in parallel."
        ),
    },
    "STRATUM-CR06.1": {
        "template": (
            "{gate_agent} is supposed to review before {actor_agent} acts. But "
            "{actor_agent} reads {data_source} directly — it can {action_verb} "
            "without {gate_agent} ever seeing the content. Your review step is "
            "a dead branch in the actual data flow."
        ),
    },
    "STRATUM-008": {
        "template": (
            "{count} external API calls have no error handling. {example_api} "
            "returns a 500. Your agent crashes mid-task. No retry, no fallback, "
            "no graceful degradation. In a multi-agent pipeline, one API hiccup "
            "cascades into full system failure. Worse: some APIs return error "
            "messages that the LLM interprets as new instructions."
        ),
    },
    "STRATUM-009": {
        "template": (
            "{count} HTTP calls have no timeout. If {example_target} hangs, your "
            "agent waits forever. In a sequential crew, every downstream agent is "
            "blocked. In production, this is a silent outage — no error, no crash, "
            "just an agent that never finishes."
        ),
    },
    "STRATUM-010": {
        "template": (
            "Your {agent_count}-agent pipeline runs for ~{estimated_seconds}s, "
            "consuming ~${estimated_cost} in API calls. If it fails at step "
            "{middle_step}, everything restarts from scratch. No intermediate state "
            "saved. At scale, you pay for every failure twice."
        ),
    },
    "STRATUM-CR02": {
        "template": (
            "{chain_length}-agent chain with no validation between steps. {agent_1} "
            "produces output. {agent_2} processes it as-is. {agent_3} acts on the "
            "result. If {agent_1} produces malformed output, the corruption "
            "propagates through the entire chain unchecked. This is the agent "
            "equivalent of SQL injection — garbage in, garbage through, garbage out."
        ),
    },
}
```

Each narrative is templated with real names from the scan: crew names, agent names, tool names, data sources. The developer reads a story about THEIR code, not a generic best practice.

### 2C. Auto-Fix Engine

```python
# autofix.py

"""
Generate fixes for findings where the fix is mechanical.

Auto-fixable findings:
  STRATUM-001, BR01  → add human_input=True (CrewAI) / interrupt_before (LangGraph)
  STRATUM-002        → same, applied to destructive tools
  STRATUM-009        → add timeout=30 to requests/httpx calls

Not auto-fixable (requires developer judgment):
  CR05, CR06, CR06.1 → architectural, developer must decide
  STRATUM-008        → try/except wrapping needs sensible fallback (deferred)
  STRATUM-010        → checkpointing is framework-specific and invasive
  CR01, CR02         → architectural

Output: a unified diff (.patch file) the developer reviews before applying.
"""

import ast
import difflib


def generate_fixes(scan_result: dict, directory: str) -> list:
    """
    Returns list of Fix objects, each with:
      - finding_id, file_path, description
      - original_lines, fixed_lines (for diff generation)
    """
    fixes = []
    files_cache = {}  # filepath → content (read once)
    
    for finding in scan_result["top_paths"]:
        fid = finding["id"].split(".")[0]  # STRATUM-CR05.1 → STRATUM-CR05
        
        if fid in ("STRATUM-001", "STRATUM-BR01", "STRATUM-002"):
            fixes.extend(_fix_add_human_gate(finding, scan_result, directory, files_cache))
        
        elif fid == "STRATUM-009":
            fixes.extend(_fix_add_timeout(finding, directory, files_cache))
    
    return _deduplicate_fixes(fixes)


def _fix_add_human_gate(finding, scan_result, directory, files_cache):
    """
    CrewAI:    add human_input=True to Task() calls for affected tasks
    LangGraph: add node name to interrupt_before=[] in compile() call
    LangChain: not auto-fixable (no standard HITL mechanism)
    """
    fixes = []
    framework = _get_primary_framework(scan_result)
    
    if framework == "CrewAI":
        # The finding's evidence contains crew name and source file
        # Find Task() calls in that file that have outbound/destructive tools
        source_file = finding.get("source_file", "")
        if not source_file:
            return fixes
        
        content = _read_file(source_file, directory, files_cache)
        if not content:
            return fixes
        
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return fixes
        
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _get_call_name(node) != "Task":
                continue
            # Check if this task already has human_input=True
            if any(kw.arg == "human_input" for kw in node.keywords):
                continue
            # Check if this task has outbound/destructive tools
            # (Simplified: if finding references this file, fix all Tasks in it)
            fixed_content = _insert_kwarg_at_line(
                content, node.end_lineno or node.lineno,
                "human_input", "True"
            )
            if fixed_content and fixed_content != content:
                fixes.append(Fix(
                    finding_id=finding["id"],
                    file_path=source_file,
                    original=content,
                    fixed=fixed_content,
                    description=f"Add human_input=True to Task() at line {node.lineno}",
                ))
                content = fixed_content  # Chain fixes in same file
    
    elif framework == "LangGraph":
        # Find compile() call and add/extend interrupt_before
        for filepath in _find_python_files(directory):
            content = _read_file(filepath, directory, files_cache)
            if not content or "compile" not in content:
                continue
            try:
                tree = ast.parse(content)
            except SyntaxError:
                continue
            
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                # Match: graph.compile(...) or *.compile(...)
                if not (isinstance(node.func, ast.Attribute) and node.func.attr == "compile"):
                    continue
                
                # Get outbound node names from the finding
                node_names = _extract_node_names_from_finding(finding, scan_result)
                if not node_names:
                    continue
                
                # Check if interrupt_before already exists
                existing_ib = None
                for kw in node.keywords:
                    if kw.arg == "interrupt_before":
                        existing_ib = kw
                        break
                
                if existing_ib:
                    # Extend existing list
                    fixed_content = _extend_list_kwarg(content, existing_ib, node_names)
                else:
                    # Add new kwarg
                    fixed_content = _insert_kwarg_at_line(
                        content, node.end_lineno or node.lineno,
                        "interrupt_before", repr(node_names)
                    )
                
                if fixed_content and fixed_content != content:
                    fixes.append(Fix(
                        finding_id=finding["id"],
                        file_path=filepath,
                        original=content,
                        fixed=fixed_content,
                        description=f"Add interrupt_before={node_names} to compile()",
                    ))
    
    return fixes


def _fix_add_timeout(finding, directory, files_cache):
    """Add timeout=30 to requests.get/post/put/delete calls without timeout."""
    fixes = []
    
    for filepath in _find_python_files(directory):
        content = _read_file(filepath, directory, files_cache)
        if not content:
            continue
        if "requests." not in content and "httpx." not in content:
            continue
        
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue
        
        modified = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _get_call_chain(node)
            if name not in ("requests.get", "requests.post", "requests.put",
                           "requests.delete", "requests.patch",
                           "httpx.get", "httpx.post"):
                continue
            if any(kw.arg == "timeout" for kw in node.keywords):
                continue
            
            content = _insert_kwarg_at_line(
                content, node.end_lineno or node.lineno,
                "timeout", "30"
            )
            modified = True
        
        if modified:
            fixes.append(Fix(
                finding_id="STRATUM-009",
                file_path=filepath,
                original=_read_file(filepath, directory, files_cache),
                fixed=content,
                description=f"Add timeout=30 to HTTP calls in {filepath}",
            ))
    
    return fixes


def write_patch(fixes: list, output_path: str):
    """Write a unified diff .patch file."""
    with open(output_path, "w") as f:
        for fix in fixes:
            diff = difflib.unified_diff(
                fix.original.splitlines(keepends=True),
                fix.fixed.splitlines(keepends=True),
                fromfile=f"a/{fix.file_path}",
                tofile=f"b/{fix.file_path}",
            )
            f.writelines(diff)
            f.write("\n")


class Fix:
    def __init__(self, finding_id, file_path, original, fixed, description):
        self.finding_id = finding_id
        self.file_path = file_path
        self.original = original
        self.fixed = fixed
        self.description = description
```

**CLI integration:**

```
$ stratum scan . --fix
[normal scan output with flow map + findings]

 GENERATED FIXES (4 findings)

 stratum-fix.patch — review before applying:

   src/email_crew.py:47  Add human_input=True to Task()
   src/email_crew.py:63  Add human_input=True to Task()
   src/tools/scraper.py:12  Add timeout=30 to requests.get()
   src/tools/scraper.py:28  Add timeout=30 to requests.post()

 To apply:  git apply stratum-fix.patch
 To review: cat stratum-fix.patch
```

The developer gets a `.patch` file they review with `git diff` or apply with `git apply`. No silent code modification. A standard diff.

**In GitHub Action mode:** the `--fix` flag generates the patch, and the Action opens a PR with the fixes. This is the Dependabot model — a PR appears, the developer reviews and merges.

### 2D. pip Package

`pip install stratum-cli`, entry point `stratum = "stratum.cli:main"`. Unchanged from v2.

### 2E. Usage Telemetry

```python
@dataclass
class UsagePing:
    """~250 bytes. Sent once per scan. Anonymous. Opt-in."""
    
    # Scanner identity
    v: str
    os: str
    py: str
    
    # Project signal (anonymous, stable)
    project_hash: str           # hash(git_remote) preferred, hash(dir) fallback
    sig: str                    # topology_signature (graph fingerprint)
    
    # Framework signal
    fw: list                    # ["CrewAI", "LangGraph"]
    parse_quality: str          # "full" | "partial" | "tools_only" | "empty"
    
    # Value signal
    agents: int
    crews: int
    findings: int
    max_sev: str
    score: int
    findings_by_cat: dict       # {"security": 2, "compounding": 5, "operational": 4}
    
    # Adoption signal
    scan_source: str            # "cli" | "github_action" | "gitlab_ci" | "ci"
    duration_ms: int
    files: int
    
    # Feature engagement signal  (NEW in v3)
    flags_used: list            # ["fix", "badge", "verbose", "quiet", "json"]
    fix_count: int              # number of auto-fixes generated (0 if --fix not used)
    output_mode: str            # "default" | "verbose" | "quiet" | "json"
    
    # Debug signal
    error: str                  # "TypeError: in graph_builder" or null
    error_module: str           # "langgraph_parser" | "finding_gen" | null
```

**New v3 fields explained:**

`flags_used` — which CLI flags the developer used. Answers: is `--fix` being adopted? Are badges generating? Is `--verbose` popular (default output too sparse) or unused (default is enough)?

`fix_count` — how many auto-fixes were generated. Combined with rescan data: if a developer runs `--fix`, generates 4 fixes, and their next scan shows score decreased, auto-fix drove the improvement.

`output_mode` — which output format was used. If 40% use `--json`, there's demand for programmatic integration.

**The six critical queries:**

```sql
-- 1. PMF: Are developers coming back and improving?
SELECT 
    COUNT(DISTINCT project_hash) FILTER (WHERE scan_num > 1) as rescan_projects,
    COUNT(DISTINCT project_hash) FILTER (WHERE score < prev_score) as improved,
    ROUND(improved * 100.0 / NULLIF(rescan_projects, 0), 1) as fix_rate_pct
FROM (
    SELECT project_hash, score,
           LAG(score) OVER (PARTITION BY project_hash ORDER BY ts) as prev_score,
           ROW_NUMBER() OVER (PARTITION BY project_hash ORDER BY ts) as scan_num
    FROM pings
);
-- Target: fix_rate > 40% = PMF

-- 2. Framework investment: Where are we losing people?
SELECT fw_elem, parse_quality, COUNT(*) as scans,
       COUNT(*) FILTER (WHERE scan_num > 1) * 100.0 / COUNT(*) as rescan_pct
FROM pings, UNNEST(fw) as fw_elem
GROUP BY fw_elem, parse_quality
ORDER BY scans DESC;
-- Next parser → framework with most scans + lowest rescan_pct

-- 3. Auto-fix adoption: Is --fix driving retention?
SELECT 
    COUNT(*) FILTER (WHERE 'fix' = ANY(flags_used)) * 100.0 / COUNT(*) as fix_usage_pct,
    AVG(fix_count) FILTER (WHERE fix_count > 0) as avg_fixes,
    -- Compare rescan rate: --fix users vs non-fix users
    COUNT(*) FILTER (WHERE 'fix' = ANY(flags_used) AND scan_num > 1) * 100.0 /
    NULLIF(COUNT(*) FILTER (WHERE 'fix' = ANY(flags_used)), 0) as fix_rescan_pct,
    COUNT(*) FILTER (WHERE NOT 'fix' = ANY(flags_used) AND scan_num > 1) * 100.0 /
    NULLIF(COUNT(*) FILTER (WHERE NOT 'fix' = ANY(flags_used)), 0) as nofix_rescan_pct
FROM pings;
-- If fix_rescan_pct >> nofix_rescan_pct, auto-fix is THE feature

-- 4. Which finding categories drive behavior change?
SELECT cat, 
       AVG(count_before - count_after) as avg_resolved
FROM (
    SELECT project_hash, key as cat, value::int as count_before,
           LEAD(value::int) OVER (PARTITION BY project_hash, key ORDER BY ts) as count_after
    FROM pings, jsonb_each_text(findings_by_cat::jsonb)
) sub WHERE count_after IS NOT NULL
GROUP BY cat ORDER BY avg_resolved DESC;
-- "security findings get fixed (avg -2.3), operational don't (avg -0.1)"
-- → invest in making operational findings scarier or auto-fixable

-- 5. Terminal redesign: Is default output working?
SELECT output_mode, COUNT(*),
       COUNT(*) FILTER (WHERE scan_num > 1) * 100.0 / COUNT(*) as rescan_pct
FROM pings GROUP BY output_mode;
-- If default has highest rescan_pct, terminal redesign is working
-- If --verbose has highest, default is showing too little

-- 6. Badge/feature adoption
SELECT 
    unnest as flag, COUNT(*) as uses,
    COUNT(*) * 100.0 / (SELECT COUNT(*) FROM pings) as pct
FROM pings, UNNEST(flags_used)
GROUP BY unnest ORDER BY uses DESC;
-- If badge < 5%, stop investing in badges
-- If json > 30%, build API/integration features
```

---

## SPRINT 3: BATCH SCAN + ENTERPRISE FLEET REPORT

### 3A. Batch Scan Pipeline

```python
# batch/discover.py — find companies with AI agent repos

QUERIES = [
    "from crewai import Crew",
    "from langgraph.graph import StateGraph",
    "from langchain.agents import AgentExecutor",
    "from langchain.agents import create_react_agent",
    "from autogen import AssistantAgent",
]

def discover_repos(output_path: str, github_token: str):
    """
    Uses GitHub Code Search API to find repos with agent framework imports.
    Output: repos.jsonl — one line per repo with org, stars, etc.
    Rate-limited to avoid API throttling.
    """
    seen = set()
    with open(output_path, "a") as f:
        for query in QUERIES:
            for page in range(1, 11):  # Max 1000 results per query
                resp = requests.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 100, "page": page},
                    headers={"Authorization": f"token {github_token}"},
                )
                if resp.status_code == 403:
                    time.sleep(60); continue
                data = resp.json()
                for item in data.get("items", []):
                    repo = item["repository"]["full_name"]
                    if repo not in seen:
                        seen.add(repo)
                        f.write(json.dumps({
                            "repo": repo,
                            "org": repo.split("/")[0],
                            "stars": item["repository"].get("stargazers_count", 0),
                        }) + "\n")
                if len(data.get("items", [])) < 100:
                    break
                time.sleep(2)
```

```bash
# batch/scan_one.sh — scan a single repo with graceful failure

#!/bin/bash
REPO=$1; TIMEOUT=${2:-120}; OUTDIR=${3:-/data/profiles}

timeout 30 git clone --depth 1 "https://github.com/$REPO.git" /tmp/scan_target 2>/dev/null
[ $? -ne 0 ] && echo "{\"repo\":\"$REPO\",\"error\":\"clone_failed\"}" >> "$OUTDIR/errors.jsonl" && exit 1

timeout $TIMEOUT stratum scan /tmp/scan_target --json --quiet 2>/dev/null > /tmp/result.json
EXIT=$?

if [ $EXIT -eq 0 ]; then
    python3 -c "
import json
r = json.load(open('/tmp/result.json'))
r['_batch'] = {'repo': '$REPO', 'org': '${REPO%%/*}'}
json.dump(r, open('$OUTDIR/${REPO//\//__}.json', 'w'))"
else
    echo "{\"repo\":\"$REPO\",\"error\":\"scan_failed\",\"exit\":$EXIT}" >> "$OUTDIR/errors.jsonl"
fi
rm -rf /tmp/scan_target /tmp/result.json
```

**Expected yield:**
```
~50,000 repos discovered
  CrewAI:    ~10K (20%) → ~8K full profiles
  LangGraph:  ~7.5K (15%) → ~6K full profiles
  LangChain: ~15K (30%) → ~12K partial profiles
  Other:     ~17.5K → tools_only or empty

Full profiles: ~14,000
Partial profiles: ~12,000
Total usable: ~26,000
```

### 3B. Connectable Surface Validation

Run during batch scan to test whether Phase 3 connectable surfaces actually work:

```python
def validate_connections(profiles_by_org: dict) -> dict:
    """
    Test cross-project connection quality on real multi-org data.
    Only analyze orgs with 3+ projects.
    """
    multi_orgs = {k: v for k, v in profiles_by_org.items() if len(v) >= 3}
    
    results = {
        "orgs_analyzed": len(multi_orgs),
        "model_overlap": 0,     # orgs where 2+ projects share an LLM
        "specific_env_overlap": 0,  # orgs with specific (non-universal) env var overlap
        "vector_overlap": 0,    # orgs where 2+ projects share a vector store type
        "any_connection": 0,    # orgs with any cross-project connection
        "universal_only": 0,    # orgs where only OPENAI_API_KEY matched (noise)
    }
    
    for org, projects in multi_orgs.items():
        models = [set(m["model"] for m in p.get("llm_models", [])) for p in projects]
        specific_envs = [set(e["name"] for e in p.get("env_var_names_specific", [])) for p in projects]
        vectors = [set(p.get("vector_stores", [])) for p in projects]
        
        has_model = _sets_overlap(models)
        has_env = _sets_overlap(specific_envs)
        has_vector = _sets_overlap(vectors)
        
        if has_model: results["model_overlap"] += 1
        if has_env: results["specific_env_overlap"] += 1
        if has_vector: results["vector_overlap"] += 1
        if has_model or has_env or has_vector: results["any_connection"] += 1
    
    # Decision thresholds:
    # any_connection > 40%: connectable surfaces work → invest in Phase 3 visualization
    # any_connection < 20%: static analysis can't infer topology → rethink Phase 3
    # universal_only > specific_env_overlap: env var classification needs tuning
    return results
```

This is a hypothesis test, not a feature. If cross-project connections are too noisy or too rare, Phase 3 needs a different approach.

### 3C. Company Targeting

```sql
-- Find outbound targets: companies with 3+ agent repos
SELECT org,
       COUNT(*) as repos,
       COUNT(*) FILTER (WHERE parse_quality IN ('full', 'partial')) as usable_repos,
       AVG(risk_score) as avg_risk,
       MAX(risk_score) as max_risk,
       COUNT(*) FILTER (WHERE max_sev = 'critical') as critical_repos,
       array_agg(DISTINCT fw_elem) as frameworks,
       array_agg(DISTINCT model_elem) as models
FROM batch_profiles,
     UNNEST(frameworks) as fw_elem,
     UNNEST(llm_models) as model_elem
GROUP BY org
HAVING COUNT(*) >= 3
ORDER BY repos DESC;

-- Expected: ~500-1000 companies with 3+ agent repos
-- Top 100 by repo count are the outbound targets
```

### 3D. Enterprise Fleet Report (PDF)

Template-driven PDF generated from batch scan data for a specific company.

```
 ┌──────────────────────────────────────────────────────────┐
 │  ACME Corp — AI Agent Fleet Assessment                   │
 │  February 2026                                           │
 │                                                           │
 │  8 agent projects · 47 agents · 3 frameworks             │
 │  Fleet Risk Score: 64/100 (73rd percentile)              │
 │  Critical findings: 7 across 3 projects                  │
 │  4 findings match known breach patterns                  │
 │                                                           │
 │  ⚠ TOP RISK: 6 of 8 projects depend on gpt-4o           │
 │    Single-provider outage affects 75% of your AI fleet   │
 │                                                           │
 │  TOP ACTION: Add human review on outbound tasks          │
 │  Resolves 11 findings across 5 projects (5 min each)     │
 └──────────────────────────────────────────────────────────┘

 Page 2: Project table (name, score, framework, critical, maturity)
 Page 3: Model dependency map (concentration risk)
 Page 4: Shared service map (coupling from specific env vars)
 Page 5: Breach pattern matches
 Page 6: What-if roadmap (aggregated controls across fleet)
 Page 7: Methodology + "runtime would reveal live behavior" CTA
```

Implementation: reportlab or WeasyPrint. One Python script, one Jinja template, one function call per company.

**The outbound flow:**

1. Batch scan finds ACME has 6+ agent repos with critical findings
2. Generate fleet report PDF
3. Find Head of AI / VP Eng on LinkedIn
4. Email: "We scanned ACME's public AI agent repos and found things your team should know about. Report attached. 15 min call?"
5. They open PDF, see their projects with findings they didn't know about
6. Reply → demo on one of their repos live
7. Pilot: scan private repos via GitHub Action
8. Contract: team plan

Time to first dollar: 4-6 weeks.

---

## SPRINT 4: GITHUB ACTION + ORGANIC GROWTH

### 4A. GitHub Action

Scan + PR comment + auto-fix PR + profile upload. The auto-fix PR is the Dependabot experience:

```yaml
name: 'Stratum AI Security Scan'
inputs:
  fail-on: { default: 'none' }
  auto-fix: { default: 'false' }
  upload: { default: 'true' }
  stratum-token: { default: '' }

runs:
  using: 'composite'
  steps:
    - run: pip install stratum-cli
      shell: bash
    
    - id: scan
      run: |
        stratum scan . --json > /tmp/stratum-result.json
        stratum scan . --quiet > /tmp/stratum-summary.txt
        SCORE=$(python3 -c "import json; print(json.load(open('/tmp/stratum-result.json'))['risk_score'])")
        echo "score=$SCORE" >> $GITHUB_OUTPUT
      shell: bash
    
    - if: github.event_name == 'pull_request'
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const summary = fs.readFileSync('/tmp/stratum-summary.txt', 'utf8');
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner, repo: context.repo.repo,
            body: `## 🔍 Stratum\n\nRisk Score: **${{ steps.scan.outputs.score }}/100**\n\n\`\`\`\n${summary}\n\`\`\`\n\n<sub>[Stratum](https://stratum.dev)</sub>`
          });
    
    - if: inputs.auto-fix == 'true'
      run: |
        stratum scan . --fix --patch-output /tmp/stratum-fix.patch
        [ -s /tmp/stratum-fix.patch ] && git apply /tmp/stratum-fix.patch
      shell: bash
    
    - if: inputs.auto-fix == 'true' && hashFiles('/tmp/stratum-fix.patch') != ''
      uses: peter-evans/create-pull-request@v5
      with:
        commit-message: 'fix: apply Stratum security auto-fixes'
        title: '🔍 Stratum: Auto-fix agent security findings'
        branch: stratum/auto-fix
    
    - if: inputs.upload == 'true' && inputs.stratum-token != ''
      run: |
        python3 -c "
        import json, urllib.request
        p = json.load(open('/tmp/stratum-result.json'))
        p['project_name'] = '${{ github.event.repository.name }}'
        p['repo_url'] = 'https://github.com/${{ github.repository }}'
        p['org_id'] = '${{ github.repository_owner }}'
        p['branch'] = '${{ github.ref_name }}'
        p['commit_sha'] = '${{ github.sha }}'[:12]
        p['scan_source'] = 'github_action'
        urllib.request.urlopen(urllib.request.Request(
            'https://api.stratum.dev/v1/profiles',
            data=json.dumps(p).encode(),
            headers={'Content-Type':'application/json','Authorization':'Bearer ${{ inputs.stratum-token }}'},
            method='POST'))
        "
      shell: bash
```

### 4B. Phase 2 Trigger

When upload API shows 3+ repos from an org AND they didn't come from outbound (organic adoption):

1. Generate fleet report from uploaded profiles
2. Email to identifiable team lead
3. CTA: "Want this as a live dashboard? Join the beta."

Build the dashboard web app only after 5+ orgs respond "yes."

---

## SPRINT 5: ECOSYSTEM DATA + BENCHMARKS

### 5A. "State of AI Agent Security" Report

Generated from 26,000 batch scan profiles. Published as content marketing.

Key statistics: framework distribution, maturity score distribution, most common gaps, model dependency concentration, breach pattern prevalence, average blast radius by framework, top 10 anti-patterns.

### 5B. Percentile Benchmarks in Scanner

After batch data exists, terminal output includes:

```
 RISK SCORE  ████████████████████░░░░░░░░░░  69/100  (73rd percentile)
             Higher risk than 73% of 14,000 scanned projects.
```

"69/100" is abstract. "Worse than 73% of projects" is concrete, competitive, and motivating.

---

## WHAT v3 DOES NOT INCLUDE

**Dashboard web app.** Build after 5+ orgs request it from fleet report outreach.

**AutoGen parser.** 5% of audience. Build when telemetry shows demand.

**STRATUM-008 auto-fix.** try/except wrapping needs sensible fallback behavior per function. Deferred — the other 3 auto-fix types ship first.

**Runtime SDK.** Phase 4. Graph model is already compatible.

**LCEL chain parsing.** Low incremental value over AgentExecutor parser.

---

## BUILD ORDER

```
Sprint 1 (Days 1-7): Framework parsers + connectable surfaces
  Day 1-2: Refactor scanner → framework dispatcher
  Day 3-4: LangGraph parser + test on real repos
  Day 5-6: LangChain parser + test on real repos
  Day 7:   Connectable surfaces + scanner bug fixes + new profile fields

Sprint 2 (Days 8-14): Terminal + auto-fix + pip + telemetry
  Day 8-9:   Terminal redesign (flow map hero + attack narratives)
  Day 10-11: Auto-fix engine (human gate + timeout + patch generation)
  Day 12-13: pip package + usage telemetry with engagement tracking
  Day 14:    Integration test (pip install → scan → --fix → rescan → score drops)

Sprint 3 (Days 15-22): Batch scan + enterprise outreach
  Day 15-16: Batch scan pipeline (discover + scan_one + graceful failure)
  Day 17-19: Run batch scan (~50K repos)
  Day 20:    Company targeting + connection validation
  Day 21-22: Fleet report PDF template + first 10 outbound emails

Sprint 4 (Days 23-30): GitHub Action + organic growth
  Day 23-24: GitHub Action (scan + comment + auto-fix PR + upload)
  Day 25-26: Upload API (Supabase)
  Day 27-30: Outreach to 3+ repo orgs + Phase 2 trigger

Sprint 5 (Days 31-37): Ecosystem data + content
  Day 31-33: Ecosystem report from batch data
  Day 34-35: Percentile benchmarks in scanner
  Day 36-37: Landing page + waitlist
```

---

## VALIDATION TARGETS

### Indie PMF (target: A+)

```
1. 65% of scans produce ≥8 findings (framework breadth)
2. Flow map renders correctly for CrewAI, LangGraph, AND LangChain
3. Every finding shows a project-specific attack narrative
4. --fix generates valid .patch for ≥3 finding types (001, 002, 009)
5. git apply stratum-fix.patch succeeds, rescan shows lower score
6. Rescan rate > 30% within 7 days (from telemetry)
7. Fix rate (score decrease on rescan) > 40% (from telemetry)
8. --fix users rescan at higher rate than non-fix users (from telemetry)
```

### Enterprise PMF (target: A+)

```
1. Batch scan: ≥14,000 full-quality profiles
2. ≥500 companies with 3+ agent repos identified
3. Fleet report PDF generates for any org with 3+ repos
4. Model dependency concentration shown in ≥60% of multi-repo orgs
5. Fleet report cold email ≥10% reply rate
6. ≥1 pilot from outbound within 6 weeks
7. Connection validation: ≥40% of multi-repo orgs have meaningful
   (non-universal) cross-project connections
```

### Telemetry (target: A+)

```
Every field maps to a decision:
  project_hash       → rescan rate (PMF)
  fw + parse_quality → next framework parser
  findings_by_cat    → which categories drive behavior change
  flags_used         → feature engagement (--fix, --badge, --verbose, --json)
  fix_count          → auto-fix adoption + impact on retention
  output_mode        → terminal redesign effectiveness
  scan_source        → CI adoption
  error + module     → debug priority

Phase transition signals:
  1→2: upload API shows 3+ repos from org (organic)
       OR batch scan finds company target (outbound)
  2→3: connection validation shows ≥40% meaningful overlap
  3→4: paying customer asks for runtime (sales signal)

Decided NOT to measure:
  Install-to-first-scan (pip doesn't report installs — infer from first-seen project_hash)
  Terminal scroll depth (fire-and-forget — infer from output_mode + rescan rate)
  Badge view count (tracked by badge URL server, not usage ping)
```
