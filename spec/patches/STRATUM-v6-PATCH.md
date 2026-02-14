# Stratum v6 Patch — A+ on All Dimensions

**Patch version:** v6
**Base version:** v5 (all 5 v4 bugs confirmed fixed)
**Goal:** Indie A- → A+, Enterprise A- → A+, Telemetry A+ (maintain)

---

## Research Summary

The v5 evaluation awarded A- on both Indie and Enterprise. Deep analysis reveals **6 specific blockers** — 4 Indie, 2 Enterprise. All are display-layer or data-enrichment fixes; the scoring formula, AST parser, and telemetry pipeline require no changes.

### Key research insight

The score delta problem (↓4 points for 3 findings resolved) is **not solvable by changing K or the formula**. Mathematical proof: the asymptotic curve inherently compresses deltas at high raw scores. Sweeping K from 20 to 100 only moves the delta from 2.5 to 4.5 — never above 5. Alternative formulas (sqrt, log, piecewise, composite) yield similar or worse results.

Snyk and SonarQube don't face this problem because they don't use a single aggregate score for the "progress" story. Snyk scores per-issue (0–1000). SonarQube uses quality gates (pass/fail) plus multi-metric dashboards. Neither relies on an aggregate score delta to motivate developers.

**The solution: change the display, not the formula.** Show a multi-metric progress card where the score delta is one line among several. The finding count, severity reduction, guardrail gain, and crew coverage tell the "you made real progress" story that a 4-point score delta cannot.

---

## Bug I1: Default Scan Missing Score

### Problem

The default terminal output has no risk score above the fold. The header box shows `crewai-examples · 116 files · 30 crews · 56 agents` but no score. The developer's first scan gives no risk number — they have to scroll to find it in the findings section.

The rescan shows `↓4 points (was 69)` at line 7, but the default scan has nothing at that position. This means the first-run experience has no anchor number, and the rescan's delta references a score the developer may never have consciously registered.

### Fix

Add the risk score to the header box, right after the framework line:

**Current default header:**
```
╔=================================================================╗
║  STRATUM SCAN                                                   ║
║  crewai-examples · 116 files · 30 crews · 56 agents             ║
║  Frameworks: CrewAI, LangChain, LangGraph                       ║
╚=================================================================╝
```

**Patched default header:**
```
╔=================================================================╗
║  STRATUM SCAN                                                   ║
║  crewai-examples · 116 files · 30 crews · 56 agents             ║
║  Frameworks: CrewAI, LangChain, LangGraph                       ║
║                                                                  ║
║  Risk Score: 69/100                                              ║
╚=================================================================╝
```

**Patched rescan header (unchanged, already shows delta):**
```
╔=================================================================╗
║  STRATUM SCAN                                                   ║
║  crewai-examples · 116 files · 20 crews · 56 agents             ║
║  Frameworks: CrewAI, LangChain, LangGraph                       ║
╚=================================================================╝

↓4 points (was 69)
```

### Implementation

In `render_header()`, after the framework line and before `╚`, insert:

```python
score_line = f"║  Risk Score: {profile.risk_score}/100"
score_line += " " * (BOX_WIDTH - len(score_line) - 1) + "║"
header_lines.append(score_line)
header_lines.append(f"║{' ' * (BOX_WIDTH - 2)}║")  # blank spacer
```

### Verification

- Default terminal line 13 (or wherever the header ends) shows `Risk Score: 69/100`
- Rescan does NOT duplicate the score in the header (it's already shown in the delta line)
- Score in header matches the score in telemetry ping
- Score=0 repos (none should exist with v5 floor) would show `Risk Score: 16/100` etc.

---

## Bug I2: Score Delta Display Too Thin

### Problem

The rescan shows one line: `↓4 points (was 69)`. The developer resolved 3 findings, added 25 guardrails, fixed 8 error handlers, and cleaned 10 crews out of the "with findings" list. But the terminal tells them "you moved 4 points." This is mathematically correct but emotionally underwhelming.

The core insight from SonarQube: progress is felt through **multiple metric cards**, not a single number. SonarQube's dashboard shows issues (by severity), coverage %, duplications %, and security hotspots — four independent progress indicators. Any one metric improving feels like progress even if another is flat.

### Fix

Replace the single-line delta with a **progress card** — a compact block that shows score, findings, severity, guardrails, and crew coverage as parallel metrics.

**Current rescan display (lines 7-15):**
```
↓4 points (was 69)

─── RESOLVED SINCE LAST SCAN ───────────────────────────────
 ✓ STRATUM-002  Destructive tool with no gate — RESOLVED
 ✓ STRATUM-009  No timeout on HTTP calls — RESOLVED
 ✓ STRATUM-CR06.1  Data access bypass — RESOLVED

 3 resolved · 0 new · 15 remaining
```

**Patched rescan display:**
```
─── SCAN PROGRESS ──────────────────────────────────────────

  Risk Score    65/100       ↓4 points (was 69)
  Findings      15 remaining ↓3 resolved
  Guardrails    47 detected  ↑25 since last scan
  Crews clean   12 of 20     ↑10 since last scan

─── RESOLVED ───────────────────────────────────────────────

  ✓ STRATUM-002     Destructive tool with no gate
  ✓ STRATUM-009     No timeout on HTTP calls
  ✓ STRATUM-CR06.1  Data access bypass

  3 resolved · 0 new · 15 remaining
```

The **progress card** has four lines, each with a metric name, current value, and delta. The developer sees four green indicators instead of one lukewarm number. "↑25 guardrails" and "↑10 crews clean" make the 11 human_input fixes and 8 error handler additions visible as concrete structural improvements.

### Implementation

New function `render_progress_card()` in `terminal_output.py`:

```python
def render_progress_card(current: ScanProfile, previous: ScanProfile) -> list[str]:
    """Render multi-metric progress card for rescan."""
    lines = ["─── SCAN PROGRESS ──────────────────────────────────────────", ""]
    
    # Score
    score_delta = current.risk_score - previous.risk_score
    arrow = "↓" if score_delta < 0 else "↑" if score_delta > 0 else "→"
    lines.append(f"  Risk Score    {current.risk_score}/100"
                 f"       {arrow}{abs(score_delta)} points (was {previous.risk_score})")
    
    # Findings
    f_delta = previous.finding_count - current.finding_count
    lines.append(f"  Findings      {current.finding_count} remaining"
                 f" ↓{f_delta} resolved" if f_delta > 0 
                 else f"  Findings      {current.finding_count} remaining")
    
    # Guardrails
    g_delta = current.guardrail_count - previous.guardrail_count
    if g_delta > 0:
        lines.append(f"  Guardrails    {current.guardrail_count} detected"
                     f"  ↑{g_delta} since last scan")
    
    # Crews clean (crews without findings)
    clean_now = current.crew_count - current.crews_with_findings
    clean_prev = previous.crew_count - previous.crews_with_findings
    c_delta = clean_now - clean_prev
    if c_delta > 0:
        lines.append(f"  Crews clean   {clean_now} of {current.crew_count}"
                     f"     ↑{c_delta} since last scan")
    
    lines.append("")
    return lines
```

Called from `render_rescan()` in place of the current single-line delta.

### Data requirements

The progress card needs two values not currently stored on the `ScanProfile`:

- `crews_with_findings`: integer, count of crews that have at least one finding
- `previous_guardrail_count`: from the cached prior scan

Both are already computable from existing data:
- `crews_with_findings` = len of per_crew_scores dict entries where score > 0
- `previous_guardrail_count` = stored in the `.stratum-cache.json` from the previous scan

### Verification

- Rescan shows 4-line progress card before the resolved findings list
- Each metric has a delta arrow (↓ or ↑) with the change amount
- "Crews clean" shows `12 of 20 ↑10` (was 2 of 30, now 12 of 20)
- "Guardrails" shows `47 detected ↑25`
- Score line matches the current single-line display
- If no change in a metric, omit that line (don't show "→0")

---

## Bug I3: STRATUM-001 No Partial Credit

### Problem

The developer runs `--fix`, which applies `human_input=True` to 11 crews. Guardrails jump from 22 to 47 (+25). But STRATUM-001 ("No HITL on agents with external tool access") still fires as CRITICAL with identical text. The developer did the work but gets zero credit on this specific finding.

Snyk solves this with "reachability analysis": a vulnerability's priority score drops when the vulnerable code path is partially mitigated, even though the CVE still technically applies. The finding doesn't disappear — it downgrades in severity and shows mitigation progress.

### Fix

Add **coverage tracking** and **severity downgrade** for findings that can be partially mitigated.

#### 1. Coverage ratio per finding

Each finding that involves per-path analysis (STRATUM-001, BR01) tracks:

```python
class FindingCoverage:
    finding_id: str
    total_paths: int       # total crews/agents where finding applies
    guarded_paths: int     # crews/agents where fix has been applied
    coverage_pct: float    # guarded_paths / total_paths * 100
```

For STRATUM-001 in crewai-examples:
- Pre-fix: total_paths=20 (Python-defined crews), guarded_paths=0 → 0%
- Post-fix: total_paths=20, guarded_paths=11 → 55%

#### 2. Severity downgrade rules

```python
PARTIAL_CREDIT_THRESHOLDS = {
    # coverage_pct → severity_adjustment
    0:   0,     # no change
    25: -1,     # downgrade one level (CRITICAL → HIGH)
    50: -1,     # stay at one-level downgrade  
    75: -2,     # downgrade two levels (CRITICAL → MEDIUM)
    100: None,  # finding resolves completely
}
```

For STRATUM-001 at 55% coverage: severity drops CRITICAL → HIGH.

This has a direct score impact. CRITICAL weight = 10, HIGH weight = 5. The finding's raw contribution drops from 10 to 5. Combined with the 3 other resolved findings, the total raw change becomes:

- Pre-fix raw: 82 (4×10 + 5×5 + 8×2 + 1×1)
- Post-fix raw without partial credit: 70 (4×10 + 3×5 + 7×2 + 1×1)
- Post-fix raw WITH partial credit: 65 (3×10 + 4×5 + 7×2 + 1×1)
  - STRATUM-001 moves from critical (10) to high (5) bucket

Score: 82/(82+50)×100 = 62 → 65/(65+50)×100 = 57. **Δ = -5 on the severity component alone**, plus the progress card shows "55% mitigated" on STRATUM-001.

#### 3. Terminal narrative for partially mitigated findings

**Current finding ② display (STRATUM-001):**
```
② Add human review gate for external data flows          ░ 20 min
  Resolves 1 finding (1 critical)
  
  [narrative about email agent forwarding to external services]
```

**Patched finding ② display (post-fix, partially mitigated):**
```
② Add human review gate for external data flows          ░ 20 min
  Partially mitigated: 11 of 20 crews now have HITL (55%)
  ⬤⬤⬤⬤⬤⬤⬤⬤⬤⬤⬤○○○○○○○○○  55% coverage
  
  Remaining: 9 YAML-defined crews cannot be auto-fixed.
  Run stratum scan . --fix --yaml to generate YAML patches.
  
  [narrative about remaining unguarded paths]
```

#### 4. Severity badge in finding card

Pre-fix:
```
  STRATUM-001  No HITL on agents with external tool access  CRITICAL
```

Post-fix:
```
  STRATUM-001  No HITL on agents with external tool access  HIGH ⬤⬤⬤⬤⬤⬤○○○○ 55%
```

### Implementation

In `finding_engine.py`, add after finding detection:

```python
def compute_coverage(finding: Finding, profile: ScanProfile) -> FindingCoverage:
    """Compute mitigation coverage for path-based findings."""
    if finding.rule_id not in PATH_COVERAGE_RULES:
        return None  # non-path findings don't get partial credit
    
    if finding.rule_id == "STRATUM-001":
        total_paths = len(profile.python_defined_crews)
        guarded_paths = sum(1 for crew in profile.python_defined_crews 
                           if crew.has_hitl)
        return FindingCoverage(
            finding_id=finding.id,
            total_paths=total_paths,
            guarded_paths=guarded_paths,
            coverage_pct=guarded_paths / total_paths * 100 if total_paths > 0 else 0,
        )
```

In `scoring.py`, modify severity before score calculation:

```python
def adjust_severity_for_coverage(finding: Finding, coverage: FindingCoverage) -> str:
    """Downgrade severity based on mitigation coverage."""
    if coverage is None or coverage.coverage_pct == 0:
        return finding.severity
    
    levels = ["low", "medium", "high", "critical"]
    current_idx = levels.index(finding.severity)
    
    if coverage.coverage_pct >= 75:
        adjustment = 2
    elif coverage.coverage_pct >= 25:
        adjustment = 1
    else:
        adjustment = 0
    
    new_idx = max(0, current_idx - adjustment)
    return levels[new_idx]
```

### Verification

- Pre-fix: STRATUM-001 fires as CRITICAL, 0% coverage, raw weight = 10
- Post-fix (11 of 20 guarded): STRATUM-001 fires as HIGH, 55% coverage, raw weight = 5
- Finding narrative shows progress bar and "11 of 20 crews now have HITL (55%)"
- Finding narrative explains what remains: "9 YAML-defined crews cannot be auto-fixed"
- Score delta increases from -4 to approximately -7 (exact depends on full recalculation)
- Telemetry ping includes `coverage_ratio` per finding in `finding_coverages` field
- If coverage reaches 100%: finding resolves completely (same as current behavior)

---

## Bug I4: "56-Agent Pipeline" in Secondary Findings

### Problem

The "Also worth fixing" section says "Your 56-agent pipeline has no checkpointing" and "56-agent chain with no validation between steps." But 56 is the total agent count across all 30 crews, including crews that are already clean. The relevant context is the crews-with-findings count, not the global total.

This is the same class of bug as the v4 blast radius issue (which used global 56 instead of per-crew counts), but in the secondary findings section rather than the primary findings.

### Fix

Replace global agent counts in secondary finding narratives with scoped counts.

**Current "also worth fixing":**
```
· Your 56-agent pipeline has no checkpointing
· 56-agent chain with no validation between steps
```

**Patched "also worth fixing":**
```
· Your 5 crews with findings (13 agents) have no checkpointing
· No validation between agent handoffs in StockAnalysisCrew (4 agents)
```

### Implementation

In `render_secondary_findings()`:

```python
def _scope_agent_count(finding: SecondaryFinding, profile: ScanProfile) -> str:
    """Replace global agent count with scoped count in narrative."""
    if finding.scope == "global":
        # Use crews_with_findings count instead of total agents
        crews_affected = profile.crews_with_findings_count
        agents_affected = sum(c.agent_count for c in profile.crews 
                            if c.finding_count > 0)
        return finding.narrative.replace(
            f"{profile.total_agent_count}-agent pipeline",
            f"{crews_affected} crews with findings ({agents_affected} agents)"
        ).replace(
            f"{profile.total_agent_count}-agent chain",
            f"agent handoffs in {profile.top_risk_crew.name} ({profile.top_risk_crew.agent_count} agents)"
        )
    return finding.narrative
```

### Verification

- Default "also worth fixing" shows scoped counts (not 56)
- Rescan "also worth fixing" uses updated counts (post-fix)
- If only 1 crew has findings, narrative names that crew specifically
- If all crews have findings, narrative still uses scoped count (same as total but more intentional)

---

## Bug E1: Ceiling Compression in Fleet Table

### Problem

crewAIInc/crewAI (112 findings, 11 agents) and AgentOps-AI/agentops (135 findings, 48 agents) both score 100. A CISO reviewing a fleet report can't prioritize between them. The score formula correctly caps at 100 (both have raw >> K), but the fleet view loses resolution where it matters most.

### Fix

**Don't change the formula.** Add `finding_count` as a visible secondary metric in the fleet table and use it as a tiebreaker in sort order.

**Current fleet table sort:** `risk_score DESC`

**Patched fleet table sort:** `risk_score DESC, finding_count DESC`

**Current fleet table format:**
```
FLEET RISK OVERVIEW
═══════════════════════════════════════════════════
AgentOps-AI/agentops        100  ▓▓▓▓▓▓▓▓▓▓
crewAIInc/crewAI            100  ▓▓▓▓▓▓▓▓▓▓
```

**Patched fleet table format:**
```
FLEET RISK OVERVIEW                              Findings  Agents  Providers
══════════════════════════════════════════════════════════════════════════════
AgentOps-AI/agentops        100  ▓▓▓▓▓▓▓▓▓▓     135       48     openai
crewAIInc/crewAI            100  ▓▓▓▓▓▓▓▓▓▓     112       11     anthropic, openai +2
bytedance/deer-flow          70  ▓▓▓▓▓▓▓░░░      35        3     azure_openai
langchain-ai/deepagents      66  ▓▓▓▓▓▓▓░░░      22       21     anthropic
...
```

The finding count provides instant differentiation for repos at the same score level. The agent count shows scale. The provider column shows model dependency — the fleet's killer insight.

### Implementation

In `render_fleet_table()`:

```python
def render_fleet_table(batch: list[BatchResult]) -> list[str]:
    # Sort: score DESC, finding_count DESC
    sorted_batch = sorted(batch, key=lambda r: (-r.risk_score, -r.finding_count))
    
    lines = [
        "FLEET RISK OVERVIEW                              Findings  Agents  Providers",
        "═" * 78,
    ]
    
    for r in sorted_batch:
        bar = "▓" * (r.risk_score // 10) + "░" * (10 - r.risk_score // 10)
        providers_str = _format_providers(r.llm_providers, max_width=25)
        lines.append(
            f"{r.repo_name[:35]:35s} {r.risk_score:3d}  {bar}"
            f"  {r.finding_count:5d}  {r.agent_count:5d}     {providers_str}"
        )
    
    return lines
```

In `batch-results.json`, also add `fleet_sort_rank` field so downstream consumers preserve this ordering:

```python
for i, r in enumerate(sorted_batch):
    r["fleet_sort_rank"] = i + 1
```

### Verification

- Fleet table sorts agentops (135 findings) before crewAI (112 findings) at score=100
- Finding count and agent count columns are visible
- Provider column shows first 2–3 providers with "+N" for additional
- All 16 repos appear in the table
- Sort order is deterministic (no ties at score + finding_count level)

---

## Bug E2: Missing Provider Data for 3 Repos

### Problem

Three repos have no provider data:
- `jgravelle/AutoGroq`: frameworks=[], parse_quality=tools_only → no framework signal to infer from
- `langchain-ai/langgraph-bigtool`: frameworks=[LangChain, LangGraph], parse_quality=full → has framework but no env vars or model references
- `langchain-ai/react-agent-tool-server`: frameworks=[LangChain, LangGraph], parse_quality=full → same

### Fix

Add **framework-level provider inference** as a third tier after model detection and env var inference.

**Inference hierarchy:**
1. **Model detection** (highest confidence): AST finds `model="gpt-4o"` → provider=openai
2. **Env var inference** (medium confidence): `OPENAI_API_KEY` in env → provider=openai
3. **Framework inference** (lowest confidence): LangChain/LangGraph present → provider=openai (most common default)

**Framework inference rules:**
```python
FRAMEWORK_DEFAULT_PROVIDERS = {
    "LangChain":  ["openai"],      # LangChain defaults to OpenAI
    "LangGraph":  ["openai"],      # LangGraph inherits LangChain default
    "CrewAI":     ["openai"],      # CrewAI defaults to OpenAI
    "AutoGen":    ["openai"],      # AutoGen defaults to OpenAI
    "Haystack":   ["openai"],      # Haystack defaults to OpenAI
}
```

**Confidence field:** Add `provider_confidence` to batch records:
```json
{
  "llm_providers": ["openai"],
  "provider_confidence": "inferred_from_framework",
  "provider_confidence_note": "LangChain/LangGraph detected; OpenAI is default provider"
}
```

### Implementation

In `provider_inference.py`, add after env var inference:

```python
def infer_providers_from_framework(profile: ScanProfile) -> list[ProviderInference]:
    """Tier 3: Infer likely providers from framework choice."""
    if profile.llm_providers:  # already have providers from tier 1 or 2
        return []
    
    inferred = set()
    for fw in profile.frameworks:
        if fw in FRAMEWORK_DEFAULT_PROVIDERS:
            inferred.update(FRAMEWORK_DEFAULT_PROVIDERS[fw])
    
    return [ProviderInference(
        provider=p,
        confidence="inferred_from_framework",
        source=f"Default for {', '.join(profile.frameworks)}",
    ) for p in inferred]
```

For AutoGroq (no frameworks at all), the inference chain bottoms out with no result. This is acceptable — AutoGroq is a UI tool with no clear framework dependency. Leave it as unknown.

### Verification

- langchain-ai/langgraph-bigtool: providers=["openai"], confidence="inferred_from_framework"
- langchain-ai/react-agent-tool-server: providers=["openai"], confidence="inferred_from_framework"
- jgravelle/AutoGroq: providers=[] (no inference possible, honestly reported)
- Fleet provider concentration: OpenAI coverage increases from 62% (10/16) to 75% (12/16)
- Repos with provider data: 15/16 (was 13/16)
- Only 1 repo has no provider data (AutoGroq), which is correctly documented as `tools_only` parse quality
- `provider_confidence` field appears in batch records and telemetry ping

---

## Telemetry Additions (maintain A+)

### New fields for v6

The progress card and partial credit features generate new telemetry:

```json
{
  "progress_card_shown": true,
  "finding_coverages": {
    "STRATUM-001": { "total_paths": 20, "guarded_paths": 11, "coverage_pct": 55 }
  },
  "severity_downgrades": {
    "STRATUM-001": { "original": "critical", "adjusted": "high", "reason": "partial_mitigation_55pct" }
  },
  "crews_clean": 12,
  "crews_with_findings": 8,
  "provider_confidence_breakdown": {
    "detected": 7,
    "inferred_env_var": 6,
    "inferred_framework": 2,
    "unknown": 1
  }
}
```

### Rescan ping artifact

Capture the rescan UsagePing as a separate JSON artifact (`sample-rescan-ping.json`) alongside the existing initial-scan ping. This verifies that `is_rescan=true`, `prev_score`, `score_delta`, `resolved_count`, and `new_count` are populated correctly.

---

## Artifacts to Produce

For the v6 evaluation, produce these updated files:

1. **terminal-default-v6.txt** — Default scan with score in header
2. **terminal-rescan-v6.txt** — Rescan with progress card, partial credit on STRATUM-001
3. **evaluation-summary.json** — Updated with coverage ratios, severity downgrades, progress card data
4. **batch-results.json** — Updated with fleet_sort_rank, provider_confidence, framework-inferred providers
5. **sample-usage-ping.json** — Initial scan ping (unchanged schema, v6 fields added)
6. **sample-rescan-ping.json** — NEW: Rescan ping with delta fields populated
7. **connection-validation.json** — Updated provider concentration with new inferences

---

## Evaluation Criteria (v6 Pass/Fail)

### Indie A+ requires ALL of:

| # | Check | Pass condition |
|---|-------|---------------|
| V1 | Score in default header | Default terminal header box contains `Risk Score: NN/100` |
| V2 | Progress card on rescan | Rescan shows 4-metric card (score, findings, guardrails, crews) with deltas |
| V3 | STRATUM-001 partial credit | Post-fix STRATUM-001 shows coverage bar, severity=HIGH (was CRITICAL) |
| V4 | Score delta improved | Post-fix score delta ≥ 5 points (was 4 in v5, higher with partial credit) |
| V5 | Secondary findings scoped | "Also worth fixing" uses crews-with-findings count, not global 56 |
| V6 | Rescan crews-clean metric | Progress card shows `Crews clean: N of M ↑K` |
| V7 | v5 fixes preserved | All 10 v4→v5 bug fixes still pass (blast radius, breach matching, etc.) |

### Enterprise A+ requires ALL of:

| # | Check | Pass condition |
|---|-------|---------------|
| V8 | Fleet sort order | agentops (135 findings) sorts before crewAI (112 findings) at score=100 |
| V9 | Fleet table columns | Table shows findings, agents, and providers columns |
| V10 | Framework inference | langgraph-bigtool and react-agent-tool-server have providers=["openai"] |
| V11 | Provider confidence | batch records include `provider_confidence` field |
| V12 | Fleet coverage | 15/16 repos have provider data (only AutoGroq unknown) |

### Telemetry A+ requires ALL of:

| # | Check | Pass condition |
|---|-------|---------------|
| V13 | Rescan ping captured | sample-rescan-ping.json exists with is_rescan=true |
| V14 | Coverage in telemetry | finding_coverages field in ping with STRATUM-001 entry |
| V15 | Severity downgrade logged | severity_downgrades field in ping |
| V16 | All v5 fields preserved | 34/34 v5 fields still present |

---

## v5 Evaluation Correction

The v5 evaluation incorrectly marked "Warning annotations (☢/⚠): ✗" in both default and rescan. This was an evaluation search bug — the code checked `line.strip().startswith(('☢', '⚠'))` but the annotations appear inside box-drawing characters (`│ ☢ STRATUM-CR05: ...`). Both ☢ (critical) and ⚠ (warning) are correctly present in v5 flow maps. No fix needed.

Similarly, the v5 evaluation marked "External service icons (✉/💬/🌐): ✗" — this was checking for specific Unicode characters that may be rendered differently in the terminal capture. This should be rechecked with broader character matching in the v6 evaluation.

---

## Implementation Priority

If implementation time is constrained, prioritize in this order:

1. **I1 + I2** (score in header + progress card) — highest UX impact, no formula change
2. **E1** (fleet table columns + sort) — pure display change, immediately differentiates for CISO
3. **I3** (partial credit) — requires coverage tracking but directly improves score delta
4. **E2** (framework inference) — small code change, closes provider gap
5. **I4** (secondary finding scoping) — narrative template change, lowest risk

Total estimated effort: ~2 days for a senior developer who understands the codebase.
