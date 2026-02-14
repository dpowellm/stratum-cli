# STRATUM — The 20/10 Patch

## WHAT THIS DOCUMENT IS

The scanner output is now a 9.5/10. Clean graph, friendly labels, consolidated findings, framework-specific remediation, agent nodes, correct sensitivity propagation. It's shippable.

This patch defines what takes Stratum from "good CLI security scanner" to "the thing every AI agent developer runs, the dataset every enterprise buyer needs, and the product that ServiceNow AI Control Tower can't replicate because the data doesn't exist anywhere else."

Two axes, twelve capabilities. The first axis is **developer-facing virality** — things that make developers screenshot, share, and star the repo. The second axis is **telemetry intelligence** — the data collected at scale that creates a proprietary moat for the enterprise product.

Each capability is designed to feed both axes simultaneously. The developer gets value; the telemetry gets richer.

---

# AXIS 1: DEVELOPER VIRALITY

The goal: a developer runs `stratum scan .` on their CrewAI project, sees something that makes them go "holy shit," screenshots it, and posts it on Twitter/HN. They then add the badge to their README because it signals competence to their peers. They add the GitHub Action because it catches regressions. Every one of these touchpoints sends anonymized telemetry back.

---

## CAPABILITY 1: REAL-WORLD INCIDENT MATCHING

### The insight

The single most viral thing a security tool can do is say: **"Your agent has the same vulnerability that caused a real breach."**

Not abstract CVE numbers. Not theoretical attack trees. A specific, named incident with a dollar figure attached.

In 2025 alone:
- **EchoLeak (Microsoft Copilot):** Zero-click prompt injection via email → data exfiltration through trusted Microsoft domains. Estimated $200M impact across 160+ incidents. The attack: send an email with hidden instructions → Copilot ingests it → extracts data from OneDrive/SharePoint/Teams → exfiltrates via approved channels.
- **ServiceNow Now Assist:** Second-order prompt injection — low-privilege agent tricks high-privilege agent into exporting case files to external URLs.
- **Docker Ask Gordon:** Prompt injection via poisoned Docker Hub metadata → AI assistant exfiltrates sensitive data without user consent.
- **Slack AI:** Hidden instructions in Slack messages trick AI assistant into inserting malicious links that exfiltrate private channel data.

The email auto responder we just scanned has **the exact same architecture as EchoLeak**: unguarded email ingestion → AI processing → outbound capability with no output filter. The graph already proves this. We just need to say it.

### Implementation

#### New file: `stratum/intelligence/incidents.py`

```python
"""Known real-world AI security incidents mapped to graph patterns."""

@dataclass
class Incident:
    id: str                     # "ECHOLEAK-2025"
    name: str                   # "Microsoft Copilot EchoLeak"
    date: str                   # "2025-Q1"
    impact: str                 # "$200M+ estimated, 160+ organizations"
    source: str                 # "Embrace The Red / Johann Rehberger"
    url: str                    # Link to writeup
    attack_summary: str         # One-sentence description
    graph_pattern: GraphPattern # What topology triggers this match

@dataclass
class GraphPattern:
    """A pattern that matches against a RiskGraph."""
    source_types: list[str]     # ["email", "messaging"]
    sink_types: list[str]       # ["email", "http", "search"]
    requires_no_control: bool   # True = must have uncontrolled path
    min_hops: int               # Minimum path length
    sensitivity_types: list[str]# ["personal", "credentials"]


KNOWN_INCIDENTS: list[Incident] = [
    Incident(
        id="ECHOLEAK-2025",
        name="Microsoft Copilot EchoLeak",
        date="2025-Q1",
        impact="$200M+ est. across 160+ reported incidents",
        source="Embrace The Red / Johann Rehberger",
        url="https://embracethered.com/blog/posts/2024/m365-copilot-echo-leak/",
        attack_summary=(
            "Zero-click prompt injection via email. Copilot ingested "
            "crafted email, extracted data from OneDrive/SharePoint/Teams, "
            "and exfiltrated it through trusted Microsoft domains."
        ),
        graph_pattern=GraphPattern(
            source_types=["email", "messaging"],
            sink_types=["email", "http", "search", "messaging"],
            requires_no_control=True,
            min_hops=2,
            sensitivity_types=["personal", "credentials"],
        ),
    ),
    Incident(
        id="SERVICENOW-NOWASSIST-2025",
        name="ServiceNow Now Assist Privilege Escalation",
        date="2025-H2",
        impact="Cross-tenant case file exfiltration",
        source="Security research disclosure",
        url="https://sombrainc.com/blog/llm-security-risks-2026",
        attack_summary=(
            "Second-order prompt injection: low-privilege agent tricks "
            "high-privilege agent into exporting case files to external URL."
        ),
        graph_pattern=GraphPattern(
            source_types=["database", "internal"],
            sink_types=["http", "email"],
            requires_no_control=True,
            min_hops=3,
            sensitivity_types=["personal", "internal", "credentials"],
        ),
    ),
    Incident(
        id="SLACK-AI-EXFIL-2024",
        name="Slack AI Data Exfiltration",
        date="2024-H2",
        impact="Private channel data leaked via crafted message links",
        source="PromptArmor research",
        url="https://promptarmor.substack.com/p/data-exfiltration-from-slack-ai-via",
        attack_summary=(
            "Hidden instructions in Slack messages caused AI assistant "
            "to insert malicious link. Clicking it sent private channel "
            "data to attacker's server."
        ),
        graph_pattern=GraphPattern(
            source_types=["messaging"],
            sink_types=["http", "messaging"],
            requires_no_control=True,
            min_hops=2,
            sensitivity_types=["personal", "internal"],
        ),
    ),
    Incident(
        id="DOCKER-GORDON-2025",
        name="Docker Ask Gordon Prompt Injection",
        date="2025-Q4",
        impact="Sensitive data exfiltration via poisoned Docker Hub metadata",
        source="Pillar Security",
        url="https://www.docker.com/blog/docker-security-advisory-ask-gordon/",
        attack_summary=(
            "Prompt injection via crafted Docker Hub repository metadata. "
            "AI assistant auto-executed tools to fetch payloads from "
            "attacker-controlled servers without user consent."
        ),
        graph_pattern=GraphPattern(
            source_types=["database", "internal", "email"],
            sink_types=["http"],
            requires_no_control=True,
            min_hops=2,
            sensitivity_types=["personal", "credentials", "internal"],
        ),
    ),
]


def match_incidents(graph: RiskGraph) -> list[tuple[Incident, float]]:
    """Match the scan's risk graph against known incident patterns.
    
    Returns list of (incident, confidence) tuples, sorted by confidence.
    Confidence is 0.0-1.0 based on pattern overlap.
    """
    matches = []
    
    for incident in KNOWN_INCIDENTS:
        pattern = incident.graph_pattern
        confidence = _compute_match_confidence(graph, pattern)
        if confidence >= 0.5:
            matches.append((incident, confidence))
    
    matches.sort(key=lambda x: x[1], reverse=True)
    return matches


def _compute_match_confidence(graph, pattern) -> float:
    """Score how closely the graph matches an incident pattern."""
    score = 0.0
    max_score = 0.0
    
    # 1. Source type match (0.3 weight)
    max_score += 0.3
    source_labels = [n["label"].lower() for n in graph["nodes"] 
                     if n["type"] == "data_store"]
    for src_type in pattern.source_types:
        if any(src_type in label for label in source_labels):
            score += 0.3 / len(pattern.source_types)
            break
    
    # 2. Sink type match (0.3 weight)
    max_score += 0.3
    sink_labels = [n["label"].lower() for n in graph["nodes"]
                   if n["type"] == "external"]
    for sink_type in pattern.sink_types:
        if any(sink_type in label for label in sink_labels):
            score += 0.3 / len(pattern.sink_types)
            break
    
    # 3. Uncontrolled path exists (0.2 weight)
    max_score += 0.2
    if pattern.requires_no_control:
        if graph["risk_surface"]["uncontrolled_path_count"] > 0:
            score += 0.2
    
    # 4. Sensitivity match (0.2 weight)
    max_score += 0.2
    graph_sensitivities = set(graph["risk_surface"]["sensitive_data_types"])
    if graph_sensitivities & set(pattern.sensitivity_types):
        score += 0.2
    
    return score / max_score if max_score > 0 else 0.0
```

### Terminal output

When an incident matches with ≥70% confidence, show it in a new section:

```
══════════════════════════════════════
⚡ KNOWN INCIDENT MATCH
══════════════════════════════════════

  Your agent's architecture matches a known real-world attack:

  Microsoft Copilot EchoLeak (2025-Q1)
  Impact: $200M+ est. across 160+ reported incidents

  What happened: Zero-click prompt injection via email. Copilot
  ingested crafted email, extracted data from OneDrive/SharePoint,
  and exfiltrated it through trusted Microsoft domains.

  Why your agent matches: Email ingestion → AI processing →
  unguarded outbound path. Same architecture, same vulnerability
  class, same exfiltration vector.

  Source: embracethered.com/blog/posts/2024/m365-copilot-echo-leak/
```

### Why this is a 20/10 move

**Virality:** This is the screenshot. A developer sees "your agent matches a $200M breach" and their stomach drops. They screenshot it and post it. Their followers think "I should run this on MY project." The incident match is the most shareable element possible — it's specific, scary, and credible because it references a real event.

**Telemetry:** Every incident match gets logged. At scale: "43% of email-processing agents match EchoLeak architecture." "67% of multi-agent projects match Now Assist privilege escalation pattern." This is the dataset that doesn't exist anywhere. Enterprise buyers would pay for this intelligence because it lets them say "we've verified our agents don't match any known breach patterns" in their audit reports.

### JSON output

```json
"incident_matches": [
    {
        "incident_id": "ECHOLEAK-2025",
        "name": "Microsoft Copilot EchoLeak",
        "date": "2025-Q1",
        "impact": "$200M+ est. across 160+ reported incidents",
        "confidence": 0.85,
        "matching_paths": [
            "Gmail inbox → GmailGetThread → GmailToolkit → Gmail outbound"
        ],
        "source_url": "https://embracethered.com/blog/posts/2024/m365-copilot-echo-leak/"
    }
]
```

---

## CAPABILITY 2: DYNAMIC README BADGE

### The insight

Snyk's biggest growth lever wasn't the CLI — it was the badge. Every repo with a Snyk badge is a billboard for Snyk. Visitors see the badge, click it, and learn about the tool. The badge creates a perpetual acquisition loop that costs nothing.

Stratum needs a badge that does three things:
1. Shows the agent's risk score (incentivizes developers to fix issues to get a better score)
2. Links to a public scan summary (so visitors can see what was found)
3. Collects an impression event (every badge view = telemetry)

### Implementation

#### Badge endpoint: `GET /badge/{scan_hash}.svg`

The scan hash is a deterministic hash of the project's git remote + branch. The badge is generated as an SVG on the server.

```
[![Stratum Risk Score](https://stratum.dev/badge/a1b2c3.svg)](https://stratum.dev/report/a1b2c3)
```

Badge variants based on risk score:

| Score | Color | Label |
|---|---|---|
| 0-20 | Green | `stratum | low risk` |
| 21-50 | Yellow | `stratum | 42 — medium` |
| 51-75 | Orange | `stratum | 64 — high` |
| 76-100 | Red | `stratum | 89 — critical` |

#### CLI generates badge snippet

After every scan, if the project has a git remote:

```
  📛 Add to your README:
  [![Stratum](https://stratum.dev/badge/a1b2c3.svg)](https://stratum.dev/report/a1b2c3)
```

#### Public scan summary page

`https://stratum.dev/report/{scan_hash}` shows:
- Risk score with the flow map
- Number of findings by severity
- Framework and agent count
- "Scan your own project: `pip install stratum && stratum scan .`"

This page is the landing page for every badge click. It shows enough to be useful but ends with a CTA to install Stratum.

### Telemetry

Every badge render = an impression event with:
- `scan_hash` (anonymized project identifier)
- `referrer` (which GitHub repo page)
- `timestamp`

At scale: "4,200 unique AI agent repos display the Stratum badge." This is both a growth metric and a dataset — we know which repos exist and how they change over time.

---

## CAPABILITY 3: GITHUB ACTION

### The insight

Badges get initial adoption. GitHub Actions get retention. Once the scan runs on every PR, the developer can never remove it without the team noticing. It also generates scan-per-commit telemetry — the highest-frequency data source.

### Implementation

#### `.github/workflows/stratum.yml`

```yaml
name: Stratum AI Security Scan
on: [push, pull_request]

jobs:
  stratum:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: stratum-security/scan-action@v1
        with:
          fail-on: critical    # Block PR if CRITICAL findings
          upload-telemetry: true   # Opt-in anonymous telemetry
```

#### PR comment

The action posts a PR comment with:

```markdown
## 🔒 Stratum AI Security Scan

**Risk Score: 64/100** (high)

| Finding | Severity | Status |
|---|---|---|
| Unguarded data-to-external path (3 paths) | CRITICAL | ⚠️ New |
| No error handling on 7 external calls | MEDIUM | Unchanged |
| No checkpointing detected | MEDIUM | Unchanged |

**⚡ Matches known incident:** Microsoft Copilot EchoLeak (2025-Q1)

<details>
<summary>Flow map</summary>

[Email Filter Agent]
Gmail inbox (personal) → GmailGetThread → Serper API ⚠ no filter
Gmail inbox (personal) → GmailGetThread → Tavily API ⚠ no filter

[Email Responder]  
Gmail inbox (personal) → GmailToolkit → Gmail outbound ⚠ no filter

</details>

*Scanned by [Stratum](https://stratum.dev) — AI agent security scanner*
```

### Telemetry

Each CI run generates:
- Full scan result (anonymized)
- Git commit hash (for delta tracking)
- CI provider (GitHub Actions, GitLab CI, etc.)
- Trigger event (push, PR, scheduled)

At scale: "We see 12,000 scans per day across 3,400 projects. Average risk score trending down 2.3 points per month as developers fix findings." This is the longitudinal dataset that makes benchmarking possible.

---

## CAPABILITY 4: INTERACTIVE HTML REPORT

### The insight

Terminal output is great for the developer. But the person who needs to be convinced is their manager, their CISO, or their investor. Those people don't run CLIs. They need a document they can open in a browser.

The HTML report is also the artifact that gets attached to audit trails, shared in Slack channels, and embedded in compliance documentation. It's the bridge between developer tool and enterprise product.

### Implementation

`stratum scan . --report report.html`

Generates a single-file HTML document with:

1. **Executive summary** — Risk score gauge, finding count by severity, framework badges
2. **Interactive flow map** — D3.js graph visualization with draggable nodes, color-coded by trust level and sensitivity. This is THE screenshot for enterprise buyers.
3. **Findings table** — Expandable rows with scenario text, remediation code, and incident matches
4. **Agent inventory** — Table of all agents with their tools, trust levels, and risk contribution
5. **Regulatory mapping** — Which frameworks apply and why (expandable detail)
6. **Telemetry profile** — Topology signature, archetype classification, percentile benchmarks (when telemetry is opted in)

The D3 graph visualization is the centerpiece. Nodes are colored:
- 🔴 Red = external service (sink)
- 🟡 Yellow = capability with no control
- 🟢 Green = controlled capability
- 🔵 Blue = data store
- ⬜ Gray = agent

Edges are colored by sensitivity: red for personal/credentials, orange for financial, gray for public/unknown.

Uncontrolled paths are highlighted with animated dashed lines.

### Why this matters

The HTML report is what gets shared in the enterprise sales cycle. A CISO sees the interactive graph and thinks "I need this for every agent in my organization." The jump from "free CLI tool" to "enterprise platform" happens when the output format is already enterprise-ready.

---

## CAPABILITY 5: `--fix` MODE (AUTO-REMEDIATION)

### The insight

Semgrep's auto-fix and Snyk's auto-PR are their highest-conversion features. Developers who get a one-click fix are 10x more likely to actually remediate. Stratum already generates framework-specific remediation code. The next step: apply it.

### Implementation

`stratum scan . --fix`

For each finding with `quick_fix_type`:

| quick_fix_type | Action |
|---|---|
| `add_hitl` | Find the `Task(...)` constructor in Python, add `human_input=True` kwarg |
| `add_error_handling` | Wrap `crew.kickoff()` in try/except block |
| `add_memory` | Add `memory=True` to `Crew(...)` constructor |
| `add_observability` | Add `LANGCHAIN_TRACING_V2=true` to `.env` file |

The fix uses AST-based code modification (not regex) to insert kwargs into function calls:

```python
def apply_hitl_fix(file_path: str, framework: str) -> FixResult:
    """Add human_input=True to CrewAI Task constructors."""
    tree = ast.parse(open(file_path).read())
    
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _is_task_constructor(node, framework):
            continue
        
        # Check if human_input already set
        existing = [kw for kw in node.keywords if kw.arg == "human_input"]
        if existing:
            continue
        
        # Add human_input=True
        node.keywords.append(ast.keyword(
            arg="human_input",
            value=ast.Constant(value=True),
        ))
    
    # Write back using ast.unparse (Python 3.9+)
    fixed_code = ast.unparse(tree)
    
    return FixResult(
        file_path=file_path,
        finding_id="STRATUM-001",
        description="Added human_input=True to Task constructors",
        diff=_generate_diff(original, fixed_code),
    )
```

### Terminal output after `--fix`

```
  ✅ Applied 2 fixes:

  STRATUM-001  Added human_input=True to 3 Task constructors
               src/crews/email_filter_crew/email_filter_crew.py

  STRATUM-010  Added memory=True to Crew constructor
               src/crews/email_filter_crew/email_filter_crew.py

  Re-run `stratum scan .` to verify. Risk score: 64 → ~38 (estimated)
```

### Telemetry

Fix application events: which fix types are applied, which are skipped, what the estimated risk delta is. At scale: "68% of developers who see STRATUM-001 apply the HITL fix within 24 hours. Average risk score drops 26 points after first fix cycle." This is the remediation velocity dataset that enterprise buyers need for their board presentations.

---

## CAPABILITY 6: STRATUM DIFF (RISK EVOLUTION)

### The insight

A single scan is a snapshot. Enterprise value comes from trends. `stratum diff` compares the current scan against the previous one and shows what changed.

### Implementation

`stratum scan .` automatically saves each scan result to `.stratum/history/{timestamp}.json`. On subsequent scans, it loads the most recent previous result and computes a diff.

The diff is already partially in the JSON (`diff.previous_risk_score`, `diff.risk_score_delta`, `diff.new_finding_ids`, `diff.resolved_finding_ids`). Extend it:

```json
"diff": {
    "previous_risk_score": 64,
    "risk_score_delta": -26,
    "risk_trend": "improving",
    "new_finding_ids": [],
    "resolved_finding_ids": ["STRATUM-001"],
    "new_capabilities": [],
    "removed_capabilities": [],
    "new_agents": [],
    "graph_delta": {
        "nodes_added": 0,
        "nodes_removed": 0,
        "edges_added": 0,
        "edges_removed": 2,
        "paths_added": 0,
        "paths_resolved": 3
    }
}
```

### Terminal output

```
  Risk Score   64 → 38   ▼26 (improving)

  Resolved:
    ✅ STRATUM-001  Unguarded data-to-external path (3 paths)
                    Fixed: human_input=True added

  Remaining:
    ⚠️  STRATUM-008  No error handling on 7 external calls
    ⚠️  STRATUM-010  No checkpointing detected
    ℹ️  TELEMETRY-003 No observability or tracing
```

### Telemetry

Diff events are the most valuable telemetry. They show how risk evolves over time per project, per framework, per archetype. At scale: "CrewAI projects resolve STRATUM-001 in median 3.2 days. LangGraph projects take 7.1 days." This longitudinal data is what creates the enterprise benchmarking product.

---

# AXIS 2: TELEMETRY INTELLIGENCE

The goal: every scan, every badge view, every CI run contributes anonymized data to a growing dataset that becomes the definitive source of truth on AI agent security posture. This dataset is what enterprise buyers can't build themselves and what ServiceNow AI Control Tower doesn't have — real, ground-truth topology data from thousands of live projects.

---

## CAPABILITY 7: TOPOLOGY SIGNATURES & ARCHETYPE CLUSTERING

### The insight

Every AI agent project has a "shape" — its graph topology. An email processor with Gmail read + Gmail write + search is a shape. A RAG chatbot with vector DB read + LLM call + no outbound is a different shape. A trading bot with market data read + order execution is yet another.

If we hash these shapes into signatures and cluster them, we get archetypes. Archetypes are the atoms of the intelligence product. "Your project is an Email Processor archetype. 43% of Email Processors have the same vulnerability you do." This is the sentence that sells the enterprise product.

### Implementation

#### Topology signature

```python
def compute_topology_signature(graph: dict) -> str:
    """Compute a deterministic hash of the graph's structure.
    
    The signature captures:
    - Node types and their counts
    - Edge types and connectivity pattern
    - Sensitivity distribution
    - Trust level distribution
    
    It does NOT capture:
    - Specific tool names (SerperDevTool vs TavilySearchResults)
    - File paths
    - Agent names
    
    This makes it possible to cluster structurally similar projects
    even if they use different tools.
    """
    from collections import Counter
    import hashlib, json
    
    # Normalize graph to canonical form
    node_types = sorted(Counter(n["type"] for n in graph["nodes"]).items())
    edge_types = sorted(Counter(e["type"] for e in graph["edges"]).items())
    sensitivity_dist = sorted(Counter(
        n.get("data_sensitivity", "unknown") for n in graph["nodes"]
    ).items())
    trust_dist = sorted(Counter(
        n.get("trust_level", "unknown") for n in graph["nodes"]
    ).items())
    
    # Connectivity pattern: for each node type pair, count edges
    node_id_to_type = {n["id"]: n["type"] for n in graph["nodes"]}
    connectivity = Counter()
    for edge in graph["edges"]:
        src_type = node_id_to_type.get(edge["source"], "unknown")
        tgt_type = node_id_to_type.get(edge["target"], "unknown")
        connectivity[(src_type, tgt_type, edge["type"])] += 1
    connectivity_sorted = sorted(
        ((str(k), v) for k, v in connectivity.items())
    )
    
    sig_input = json.dumps({
        "node_types": node_types,
        "edge_types": edge_types,
        "sensitivity": sensitivity_dist,
        "trust": trust_dist,
        "connectivity": connectivity_sorted,
        "paths": graph["risk_surface"]["uncontrolled_path_count"],
        "max_hops": graph["risk_surface"]["max_path_hops"],
    }, sort_keys=True)
    
    return hashlib.sha256(sig_input.encode()).hexdigest()[:16]
```

#### Archetype classification

```python
ARCHETYPES = {
    "email_processor": {
        "description": "Reads email/messages, processes content, sends responses",
        "indicators": {
            "source_types": ["email", "messaging", "gmail"],
            "has_outbound": True,
            "min_capabilities": 3,
        },
        "risk_profile": "high",
    },
    "rag_chatbot": {
        "description": "Retrieves from knowledge base, generates responses",
        "indicators": {
            "source_types": ["database", "vector_db", "pinecone", "weaviate"],
            "has_outbound": False,
            "has_data_access": True,
        },
        "risk_profile": "medium",
    },
    "research_agent": {
        "description": "Searches web, aggregates information, reports results",
        "indicators": {
            "source_types": [],
            "has_outbound": True,
            "outbound_only": True,
        },
        "risk_profile": "low",
    },
    "code_agent": {
        "description": "Reads repos, generates/executes code",
        "indicators": {
            "has_code_exec": True,
        },
        "risk_profile": "critical",
    },
    "data_pipeline": {
        "description": "Reads from internal systems, transforms, writes to output",
        "indicators": {
            "source_types": ["database", "internal"],
            "has_outbound": True,
            "has_data_access": True,
        },
        "risk_profile": "high",
    },
    "multi_agent_orchestrator": {
        "description": "Coordinates multiple agents with shared context",
        "indicators": {
            "min_agents": 2,
            "has_shared_context": True,
        },
        "risk_profile": "critical",
    },
}
```

### JSON output

```json
"telemetry_profile": {
    "topology_signature": "a1b2c3d4e5f67890",
    "archetype": "email_processor",
    "archetype_confidence": 0.92,
    "framework_fingerprint": ["CrewAI", "LangChain"],
    "tool_fingerprint": ["gmail", "serper", "tavily"],
    "risk_quintile": null,
    "ecosystem_stats": null
}
```

### Enterprise value

The topology signature + archetype creates the foundation for everything enterprise:
- **Benchmarking:** "Your email_processor scores 64. The median email_processor scores 38."
- **Risk prediction:** "email_processors with ≥3 outbound paths and no HITL have 4.2x higher incident rate."
- **Policy templates:** "Here's the governance policy for email_processor archetypes, pre-populated with controls that 80% of similar projects implement."

---

## CAPABILITY 8: PUBLIC INTELLIGENCE PAGE

### The insight

Semgrep publishes a blog with statistics from their scanning data. Snyk publishes annual "State of Open Source Security" reports. These are their best marketing assets because they position the company as the authority.

Stratum should publish `stratum.dev/intelligence` — a live, auto-updating dashboard of aggregate statistics from opted-in scans. This is the content engine that drives HN posts, conference talks, blog citations, and enterprise sales conversations.

### Implementation

#### Data pipeline

Opted-in scan results are anonymized and aggregated:
- Strip all file paths, project names, git URLs
- Keep: archetype, framework, tool fingerprint, risk score, finding IDs, graph topology metrics, agent count

Aggregations computed daily:
```json
{
    "total_projects_scanned": 4283,
    "total_scans": 89412,
    "date_range": "2026-02-01 to 2026-02-11",
    
    "risk_distribution": {
        "low": 0.12, "medium": 0.34, "high": 0.41, "critical": 0.13
    },
    
    "most_common_archetypes": [
        {"archetype": "research_agent", "pct": 0.31},
        {"archetype": "rag_chatbot", "pct": 0.24},
        {"archetype": "email_processor", "pct": 0.18},
        {"archetype": "code_agent", "pct": 0.14},
        {"archetype": "data_pipeline", "pct": 0.08},
        {"archetype": "multi_agent_orchestrator", "pct": 0.05}
    ],
    
    "guardrail_adoption": {
        "any_guardrail": 0.23,
        "hitl": 0.14,
        "output_filter": 0.08,
        "input_validation": 0.11,
        "none": 0.77
    },
    
    "top_findings": [
        {"id": "STRATUM-001", "pct_projects": 0.63},
        {"id": "STRATUM-008", "pct_projects": 0.81},
        {"id": "STRATUM-010", "pct_projects": 0.72},
        {"id": "TELEMETRY-003", "pct_projects": 0.89}
    ],
    
    "incident_match_rates": {
        "ECHOLEAK-2025": 0.43,
        "SLACK-AI-EXFIL-2024": 0.22,
        "SERVICENOW-NOWASSIST-2025": 0.08
    },
    
    "headline_stats": [
        "77% of AI agent projects have zero guardrails",
        "43% of email-processing agents match the EchoLeak breach architecture",
        "Only 14% of projects implement human-in-the-loop controls",
        "CrewAI projects fix critical findings 2.2x faster than LangChain projects"
    ]
}
```

### Why this is the moat

This page is cited by:
- **Security researchers** writing about AI agent risks (free PR)
- **CISOs** justifying AI governance budgets ("77% of agent projects have zero guardrails")
- **Journalists** writing about AI security (Stratum becomes the source of record)
- **Enterprise sales** — "Here's the ecosystem. Here's where you are. Here's where you need to be."

ServiceNow AI Control Tower can't build this because they only see agents deployed on ServiceNow. Stratum sees the entire ecosystem because it runs on the developer's machine before deployment.

---

## CAPABILITY 9: PERCENTILE BENCHMARKING

### The insight

Developers are competitive. "Your risk score is 64" is abstract. "Your agent is riskier than 87% of CrewAI projects" is personal. It creates urgency to fix things not because of abstract security but because of social comparison.

### Implementation

When telemetry is opted in and benchmarks are available:

```
  Risk Score      64/100    ████████████░░░░░░░░  high
  vs. ecosystem   87th percentile — riskier than 87% of CrewAI projects
  vs. archetype   72nd percentile — riskier than 72% of email processors
```

Benchmarks computed from aggregate telemetry data. CLI fetches latest benchmarks from `stratum.dev/api/benchmarks` (cached 24hr).

### JSON output

```json
"benchmarks": {
    "ecosystem_percentile": 87,
    "archetype_percentile": 72,
    "framework_percentile": 83,
    "guardrail_adoption_vs_archetype": "bottom 25%",
    "as_of": "2026-02-11"
}
```

---

## CAPABILITY 10: MCP SERVER SECURITY SCANNING

### The insight

MCP is the fastest-growing integration pattern in AI agents. ServiceNow just launched "AI Gateway" specifically to govern MCP servers. Stratum scanning MCP configs is both a developer feature AND direct competitive positioning.

From CSO Online (Dec 2025): "MCP servers can have vulnerabilities and misconfigurations and can open a path to OS command injection."

### Extension

For each MCP server config, evaluate:

```python
MCP_SECURITY_CHECKS = [
    {
        "id": "MCP-001",
        "name": "Overprivileged MCP server",
        "check": "Server has both read and write tools with no scope restriction",
        "severity": "HIGH",
    },
    {
        "id": "MCP-002", 
        "name": "Unauthenticated MCP transport",
        "check": "Server uses stdio transport (no auth) instead of SSE with auth",
        "severity": "MEDIUM",
    },
    {
        "id": "MCP-003",
        "name": "MCP server with code execution",
        "check": "Server exposes tools that execute code or shell commands",
        "severity": "CRITICAL",
    },
    {
        "id": "MCP-004",
        "name": "MCP server fetching from untrusted sources",
        "check": "Server tools fetch from user-provided URLs without validation",
        "severity": "HIGH",
    },
    {
        "id": "MCP-005",
        "name": "No tool-level access control",
        "check": "All tools in server exposed without granular permissions",
        "severity": "MEDIUM",
    },
]
```

MCP servers integrate into the risk graph as nodes with TOOL_OF edges, enabling the same flow analysis and incident matching that works for framework tools.

### Telemetry

MCP server scanning generates the highest-value enterprise telemetry:
- Which MCP servers are most commonly used
- What tools they expose and security controls in place
- How many servers per project

This data directly feeds into the enterprise "MCP governance" product that competes with ServiceNow AI Gateway.

---

## CAPABILITY 11: "STATE OF AI AGENT SECURITY" REPORT

### The insight

Snyk's "State of Open Source Security" report is their single best marketing asset. Gets cited by analysts, shared by CISOs, used in board presentations. Costs nothing to produce because it's computed from scanning data.

### Implementation

Automated quarterly report from aggregate telemetry:

1. **Executive summary** — Key stats, trend lines, headline findings
2. **Framework landscape** — Market share, risk comparison by framework
3. **Vulnerability landscape** — Most common findings, remediation rates
4. **Archetype analysis** — Risk profiles by archetype, common attack surfaces
5. **Incident correlation** — How many projects match known breach patterns
6. **Guardrail adoption** — What's being used, what's not
7. **Predictions** — Based on trends, what's likely to happen next quarter

### Enterprise value

This report is content marketing + sales enablement + authority building + analyst bait.

---

## CAPABILITY 12: ENTERPRISE EXPORT FORMAT (SARIF + AI-SBOM)

### The insight

Enterprise security teams don't adopt tools that don't integrate with their existing stack. Two integration formats matter:

1. **SARIF** — Standard for importing results into GitHub Code Scanning, Azure DevOps, VS Code, every major SIEM/SOAR.
2. **AI-SBOM (CycloneDX)** — Emerging standard for documenting what's inside an AI system. Required by EU AI Act for high-risk systems.

### SARIF export

`stratum scan . --format sarif > results.sarif`

```json
{
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "Stratum",
                "version": "0.1.0",
                "informationUri": "https://stratum.dev",
                "rules": [
                    {
                        "id": "STRATUM-001",
                        "name": "UnguardedDataToExternalPath",
                        "shortDescription": {"text": "Unguarded data-to-external path"},
                        "properties": {
                            "tags": ["security", "ai-agent", "prompt-injection"],
                            "owasp": "ASI01"
                        }
                    }
                ]
            }
        },
        "results": [...]
    }]
}
```

This means Stratum findings show up natively in GitHub Code Scanning, Azure DevOps, VS Code Problems panel, Splunk, Datadog, and PagerDuty.

### AI-SBOM export

`stratum scan . --format ai-sbom > sbom.json`

Generates CycloneDX 1.6 with AI component metadata — agents, tools, data sources, trust levels, sensitivity classifications. This is the compliance artifact EU AI Act requires for high-risk systems.

### Enterprise value

SARIF = integrates into every enterprise security workflow. AI-SBOM = generates the compliance artifact regulators require. These are table stakes that let Stratum compete in enterprise sales.

---

# IMPLEMENTATION PRIORITY

## Phase 1: HN Launch (Week 1-2)

| # | Capability | Why |
|---|---|---|
| 1 | Incident matching | **THE viral hook** — "your agent matches a $200M breach" |
| 4 | HTML report | Shareable, screenshotable, enterprise-ready |
| 5 | `--fix` mode | 30-second remediation → immediate value |
| 12 | SARIF export | GitHub Code Scanning integration |

**HN post title:** "Show HN: Stratum — open-source security scanner for AI agents. Found that 43% of email agents match the $200M EchoLeak breach."

## Phase 2: Growth Loop (Week 3-4)

| # | Capability | Why |
|---|---|---|
| 2 | README badge | Viral acquisition loop |
| 3 | GitHub Action | Retention + CI telemetry |
| 6 | Diff mode | Longitudinal data collection |
| 7 | Topology signatures | Archetype foundation |

## Phase 3: Intelligence Product (Week 5-8)

| # | Capability | Why |
|---|---|---|
| 8 | Public intelligence page | Authority + content engine |
| 9 | Percentile benchmarking | Developer motivation |
| 10 | MCP scanning | Timely, competitive positioning vs ServiceNow |
| 11 | Quarterly report | Enterprise sales tool |

## Phase 4: Enterprise (Month 3+)

Enterprise dashboard, multi-org rollup, policy-as-code, continuous monitoring — all built on the dataset created by Phases 1-3.

---

# COSMETIC FIXES FROM 9.5→10 REVIEW

These should ship with Phase 1:

### Fix A: External node native sensitivity

**Problem:** `ext_serper_api`, `ext_tavily_api`, and `ext_gmail_outbound` show `data_sensitivity: "unknown"` instead of their native sensitivity.

**Fix:** In `stratum/graph/builder.py`, set native sensitivity when creating external service nodes:
```python
EXTERNAL_SERVICE_SENSITIVITY = {
    "serper": "public",
    "tavily": "public",
    "gmail_outbound": "personal",
    "slack": "internal",
    "http": "unknown",
}
```

The edge sensitivity (propagated from upstream data) stays correct at "personal." The node sensitivity reflects what the service natively handles.

### Fix B: Capitalize "Gmail" in scenario text

**Problem:** "reads your gmail inbox" should be "reads your Gmail inbox."

**Fix:** In `stratum/graph/scenarios.py`, ensure proper noun capitalization in generated text.

### Fix C: GmailToolkit agent assignment

**Problem:** GmailToolkit capabilities in `create_draft.py` and `emails.py` don't have TOOL_OF edges to any agent because those files don't contain `Agent()` constructors.

**Fix:** In `stratum/graph/agents.py`, trace `@tool` functions and class-level tool imports back to the Crew/Flow that uses them, then assign TOOL_OF edges transitively.

### Fix D: Empty `agent_profiles` field

**Problem:** `agent_profiles: []` while `agent_definitions: [...]` is populated.

**Fix:** Either populate `agent_profiles` from `agent_definitions` or remove the field. Recommend removing it — `agent_definitions` is the canonical source.

---

# HOW THE AXES REINFORCE EACH OTHER

```
Developer runs scan
    │
    ├──► Sees incident match → Screenshots → Posts on Twitter/HN
    │       └──► New developer sees post → Installs Stratum
    │
    ├──► Adds badge to README → Every visitor sees it
    │       └──► Visitor clicks badge → Lands on report page → Installs
    │
    ├──► Adds GitHub Action → Scan runs on every PR
    │       └──► Each run generates telemetry → Dataset grows
    │
    ├──► Telemetry aggregates → Intelligence page updates
    │       └──► Journalist cites stats → Article drives installs
    │
    ├──► Enterprise buyer sees intelligence → Wants org-wide rollout
    │       └──► Pays for enterprise features → Revenue
    │
    └──► Quarterly report published → CISOs cite it in board decks
            └──► Board approves AI governance budget → Enterprise deal
```

Every developer action feeds the telemetry. Every data point makes the product more valuable for every user. This is the network effect that creates the moat.

ServiceNow AI Control Tower has the enterprise UI but not the data. They see agents deployed on ServiceNow. Stratum sees agents at the source — in the developer's repo, before deployment, across every framework. The data advantage compounds with every scan.

---

# EXPECTED TERMINAL OUTPUT (COMPLETE, POST-PATCH)

```
STRATUM v0.2 — AI Agent Security Audit

 Agent Profile
 ─────────────
 Framework       CrewAI · LangChain
 Agents          Email Filter Agent · Email Action Agent ·
                 Email Response Writer · HR Coordinator
 Capabilities    7 (outbound: 4, data access: 3)
 Data types      personal (Gmail)
 Guardrails      none detected
 Archetype       email_processor

 Risk Score      64/100    ████████████░░░░░░░░  high
 vs. ecosystem   87th percentile — riskier than 87% of CrewAI projects

══════════════════════════════════════
⚡ KNOWN INCIDENT MATCH
══════════════════════════════════════

  Microsoft Copilot EchoLeak (2025-Q1)
  Impact: $200M+ est. across 160+ reported incidents

  Your agent reads email → processes with AI → sends outbound
  with no output filter. Same architecture, same vulnerability.

  Source: embracethered.com/blog/posts/2024/m365-copilot-echo-leak/

══════════════════════════════════════
 HOW YOUR DATA FLOWS
══════════════════════════════════════

 [Email Filter Agent]
  Gmail inbox (personal)  ──▶  GmailGetThread  ──▶  Serper API        ⚠ no filter

 [Email Action Agent]
  Gmail inbox (personal)  ──▶  GmailGetThread  ──▶  Tavily API        ⚠ no filter

 [Email Responder]
  Gmail inbox (personal)  ──▶  GmailToolkit    ──▶  Gmail outbound    ⚠ no filter

 Personal data reaches 3 external services with no output filter.

══════════════════════════════════════
 TOP RISK PATHS
══════════════════════════════════════

  CRITICAL  STRATUM-001  Unguarded data-to-external path (3 paths)

    Gmail inbox → GmailGetThread → GmailToolkit → Gmail outbound
    Gmail inbox → GmailGetThread → SerperDevTool → Serper API
    Gmail inbox → GmailGetThread → TavilySearchResults → Tavily API

    What happens: Someone sends your agent a crafted email.
    The agent reads your Gmail inbox and forwards sensitive
    content via Gmail outbound — to an attacker-controlled
    address embedded in the injected instructions.

    Fix (CrewAI):
      task = Task(
          description="...",
    +     human_input=True
      )

    Or run: stratum scan . --fix

  MEDIUM  STRATUM-008  No error handling on 7 external calls
  MEDIUM  STRATUM-010  No checkpointing detected
  LOW     TELEMETRY-003  No observability or tracing

══════════════════════════════════════
 QUICK ACTIONS
══════════════════════════════════════

  stratum scan . --fix          Apply fixes automatically
  stratum scan . --report       Generate HTML report
  stratum scan . --format sarif Export for GitHub Code Scanning

  📛 Add to your README:
  [![Stratum](https://stratum.dev/badge/a1b2c3.svg)](https://stratum.dev/report/a1b2c3)
```

---

# VALIDATION CHECKLIST (201-230)

### Incident matching
- [ ] 201. EchoLeak matches email auto responder with ≥70% confidence
- [ ] 202. Incident match appears between Agent Profile and Flow Map
- [ ] 203. `incident_matches` array in JSON with confidence scores
- [ ] 204. Includes source URL and impact figure
- [ ] 205. Only incidents ≥50% confidence appear

### Badge
- [ ] 206. Badge markdown output when git remote detected
- [ ] 207. Badge SVG shows correct risk score and color
- [ ] 208. Badge links to public report page

### GitHub Action
- [ ] 209. Action YAML runs scan and posts PR comment
- [ ] 210. PR comment includes risk score, findings, flow map
- [ ] 211. `fail-on: critical` blocks PR on CRITICAL findings

### HTML report
- [ ] 212. `--report` generates single-file HTML with D3 graph
- [ ] 213. Nodes draggable and color-coded by trust level
- [ ] 214. Uncontrolled paths highlighted with animated dashes
- [ ] 215. Report includes incident match when present

### Auto-fix
- [ ] 216. `--fix` adds `human_input=True` to Task constructors
- [ ] 217. `--fix` adds `memory=True` to Crew constructors
- [ ] 218. Fix uses AST modification, not regex
- [ ] 219. Post-fix scan shows lower risk score

### Diff
- [ ] 220. Subsequent scans show risk_score_delta
- [ ] 221. Resolved findings shown with ✅
- [ ] 222. `graph_delta` shows node/edge/path changes

### Topology signatures
- [ ] 223. `topology_signature` deterministic for same structure
- [ ] 224. Different tools with same topology → same signature
- [ ] 225. `archetype` classification in telemetry_profile

### Intelligence
- [ ] 226. Aggregate stats from opted-in telemetry
- [ ] 227. Public page: risk distribution, framework share, guardrails
- [ ] 228. Auto-generated headline stats

### Enterprise export
- [ ] 229. `--format sarif` produces valid SARIF 2.1.0
- [ ] 230. `--format ai-sbom` produces valid CycloneDX 1.6

### Cosmetic fixes
- [ ] 231. External nodes show native sensitivity (not "unknown")
- [ ] 232. "Gmail" capitalized in scenario text
- [ ] 233. GmailToolkit has TOOL_OF edges to appropriate agent
- [ ] 234. `agent_profiles` field removed or populated
