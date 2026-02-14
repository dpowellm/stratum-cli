# STRATUM TELEMETRY REDESIGN — Enterprise Intelligence Schema

## THE ENTERPRISE PILOT THAT MAKES THEM THROW MONEY

Before touching any code, here's the meeting. You're sitting across from a VP of Engineering at a Series C fintech. They have 40 agent projects across 6 teams. They just got an EU AI Act compliance audit request from their legal team. They've read about EchoLeak. They don't know what their agent fleet actually looks like.

You open a dashboard and say:

**"We scanned 52,000 agent projects across the public ecosystem. Here's where your 40 projects sit."**

Slide 1 — Portfolio Risk Map:
"Your fleet has 40 projects, 187 agents, 34 crews. 7 of your projects match the architecture of real-world AI security incidents — including 2 that match the exact pattern behind Microsoft Copilot EchoLeak. Here they are."

They lean forward.

Slide 2 — Benchmark:
"Your median blast radius is 4.1 agents per shared tool. The industry median is 2.3. For fintech specifically, it's 2.8. You're in the 94th percentile of risk — which means 94% of comparable projects are safer than yours."

Their CISO puts down their coffee.

Slide 3 — Prescriptive Remediation:
"If you add human-in-the-loop to these 3 specific tasks across 2 projects, your aggregate risk score drops 34%. We know this because across the 52,000 projects in our dataset, adding HITL to email-outbound paths reduces risk score by an average of 28 points. For your architecture pattern specifically, the reduction is 34."

They ask about pricing.

Slide 4 — Compliance Gap:
"Your agent fleet processes personal data across 11 projects with 0% control coverage on those data paths. Under EU AI Act Article 14, high-risk AI systems require human oversight. Under GDPR Article 35, processing personal data at scale requires a Data Protection Impact Assessment. Here's your gap report mapped to specific articles, with the remediation effort for each."

Legal starts nodding.

Slide 5 — Trend:
"Over the last 90 days, Team Alpha improved 22% — they added structured output validation. Team Beta got worse — they added 4 new unguarded outbound paths without controls. Here's the trajectory."

They ask when they can start.

---

**Every one of those slides requires specific data that the current telemetry doesn't capture.** The schema redesign below is reverse-engineered from those slides. Every field exists because it powers a specific enterprise claim.

---

## WHAT THE CURRENT TELEMETRY CAPTURES (13 fields)

```
topology_signature, archetype, archetype_confidence,
framework_fingerprint, capability_fingerprint,
agent_count, crew_count, shared_tool_pairs,
trust_boundary_crossings, control_coverage_pct,
max_blast_radius, blast_radius_count, control_bypass_count
```

What this lets you say at N=50,000: "67% of CrewAI projects have more than 10 outbound capabilities." Mildly interesting. Nobody pays for that.

What's missing is everything that powers the five slides above. Let me map each gap.

---

## GAP ANALYSIS: CURRENT TELEMETRY → ENTERPRISE SLIDES

### Slide 1 (Incident Pattern Matching) requires:
- ❌ Which incident patterns matched (only count exists, not IDs)
- ❌ Which findings fired (only severity counts, not finding IDs)  
- ❌ Tool inventory (only capability counts — "18 outbound" not "GmailToolkit, SerperDevTool, slack_sdk")
- ❌ External service inventory (which services does this project actually talk to?)
- ❌ Data source inventory (which sensitive data stores does it read from?)

### Slide 2 (Benchmarking) requires:
- ❌ Domain/vertical signal (is this a finance agent? HR? DevOps?)
- ❌ Per-crew blast radii (only global max, not distribution)
- ❌ Tool combination fingerprint (for "projects using this exact tool combo" cohort)
- ❌ Crew size distribution (for "projects with similar architecture" matching)
- ❌ Chain depth distribution

### Slide 3 (Prescriptive Remediation) requires:
- ❌ Finding-to-control mapping (which control would suppress which finding?)
- ❌ Per-crew risk scores (to prioritize which crews to fix)
- ❌ Guardrail effectiveness data (which guardrail types actually reduce risk?)
- ❌ What-if signal (if HITL existed on path X, finding Y would not fire)

### Slide 4 (Compliance) requires:
- ❌ Regulatory article mapping with specificity (not just "EU AI Act" but which articles)
- ❌ Data sensitivity per path (not just "has PII" but which paths carry PII to external)
- ❌ Control state per regulatory requirement
- ❌ Compliance gap count by framework

### Slide 5 (Trend) requires:
- ❌ Timestamp (exists in scan_result but not in telemetry profile)
- ❌ Delta from previous scan
- ❌ Finding churn (new findings, resolved findings)

---

## THE NEW SCHEMA

Two layers. Both stored per scan.

**Layer 1: ScanProfile** — what the scanner produces. This is the telemetry the scanner emits. For the GitHub batch scan AND for organic enterprise telemetry.

**Layer 2: RepoContext** — what the GitHub scraper adds. Repo metadata that enriches the scan. Only populated for GitHub batch scans. Enterprise customers provide their own context.

Together they form one row in the intelligence database.

---

### Layer 1: ScanProfile (scanner output)

This replaces the current 13-field telemetry_profile entirely.

```python
@dataclass
class ScanProfile:
    """
    Complete anonymized scan profile for the intelligence database.
    Every field exists because it powers a specific enterprise query.
    
    Privacy contract:
    - No file paths, function names, agent names, or code content
    - Tool names and library names are included (they're open-source identifiers, not PII)
    - External service names are included (Gmail, Slack — not secret)
    - Crew names are hashed
    - All counts, ratios, booleans, and categorical values
    """

    # ─── IDENTITY ───────────────────────────────────────────────
    # Powers: trend tracking, dedup, same-project-over-time analysis
    
    scan_id: str = ""                       # Unique scan identifier
    topology_signature: str = ""            # Hash of graph structure — same project = same signature
    schema_version: str = "2.0"
    scan_timestamp: str = ""                # ISO 8601 — powers trend analysis
    scanner_version: str = ""               # Which version of stratum produced this

    # ─── ARCHITECTURE ───────────────────────────────────────────
    # Powers: cohort matching ("projects like yours"), archetype classification
    
    archetype: str = ""                     # "single_agent", "multi_agent_pipeline", "multi_agent_orchestrator", "agent_swarm"
    archetype_confidence: float = 0.0
    
    frameworks: list = field(default_factory=list)          # ["CrewAI", "LangChain"] — actual names
    framework_versions: dict = field(default_factory=dict)  # {"crewai": "0.51.0", "langchain-core": "0.1.20"}
    
    agent_count: int = 0
    crew_count: int = 0
    files_scanned: int = 0
    is_monorepo: bool = False               # True if >3 independent crews in separate directories
    
    # Crew structure distribution — powers "similar architecture" matching
    crew_sizes: list = field(default_factory=list)          # [3, 4, 2, 2] — sorted desc
    crew_process_types: dict = field(default_factory=dict)  # {"sequential": 5, "hierarchical": 1}
    max_chain_depth: int = 0                                # Longest sequential agent chain
    avg_crew_size: float = 0.0
    has_hierarchical_crew: bool = False
    has_delegation: bool = False                             # Any manager_agent patterns

    # ─── TOOL INVENTORY ─────────────────────────────────────────
    # Powers: "projects using GmailToolkit have 94% EchoLeak match rate"
    # Powers: tool combination cohort analysis
    # These are open-source library/tool names — not PII
    
    tool_names: list = field(default_factory=list)          # ["SerperDevTool", "GmailToolkit", "ScrapeWebsiteTool", ...]
    tool_count: int = 0                                     # Unique tools
    tool_categories: dict = field(default_factory=dict)     # {"search": 3, "email": 2, "file": 2, "scraping": 2, ...}
    
    libraries: list = field(default_factory=list)           # ["crewai_tools", "langchain_community", "requests", "slack_sdk"]
    
    capability_counts: dict = field(default_factory=dict)   # {"outbound": 18, "data_access": 11, "code_exec": 0, "destructive": 1, "financial": 0}
    outbound_to_data_ratio: float = 0.0                     # outbound / data_access — high ratio = more attack surface
    
    # Tool reuse — how concentrated is tool sharing?
    tool_reuse_ratio: float = 0.0           # unique_tools / total_tool_assignments (low = lots of sharing)
    max_tool_sharing: int = 0               # Most agents sharing one tool (per-crew)
    tools_shared_by_3_plus: int = 0         # How many tools are shared by 3+ agents in a crew

    # ─── EXTERNAL SERVICES ──────────────────────────────────────
    # Powers: "your project talks to Gmail, Slack, and 2 HTTP endpoints"
    # Powers: fleet-level topology ("4 of your projects share Gmail credentials")
    # These are service categories, not endpoints
    
    external_services: list = field(default_factory=list)   # ["Gmail", "Slack", "Serper API", "HTTP endpoint", "Tavily API"]
    external_service_count: int = 0
    
    data_sources: list = field(default_factory=list)        # ["Gmail inbox", "local filesystem", "vector store", "CSV files"]
    data_source_count: int = 0
    
    # Service pattern — what integration pattern does this project use?
    has_email_integration: bool = False     # GmailToolkit, Outlook, etc.
    has_messaging_integration: bool = False # Slack, Teams, Discord
    has_web_scraping: bool = False          # ScrapeWebsiteTool, requests, BeautifulSoup
    has_database_integration: bool = False  # PostgreSQL, MongoDB, ChromaDB, etc.
    has_file_system_access: bool = False    # FileReadTool, FileManagementToolkit
    has_financial_tools: bool = False       # SEC tools, trading APIs, payment processors
    has_code_execution: bool = False        # exec(), subprocess, code interpreter

    # ─── RISK PROFILE ───────────────────────────────────────────
    # Powers: benchmarking, prioritization, trend tracking
    
    risk_score: int = 0                     # Global
    risk_score_breakdown: dict = field(default_factory=dict)  # {"base": 80, "bonus_no_guardrails": 15, ...}
    risk_scores_per_crew: list = field(default_factory=list)  # [85, 68, 38, 8] — sorted desc, anonymized
    
    # Finding inventory — which specific patterns were detected
    finding_ids: list = field(default_factory=list)          # ["STRATUM-001", "STRATUM-CR05", "STRATUM-BR01", ...]
    finding_count: int = 0
    findings_by_severity: dict = field(default_factory=dict) # {"critical": 2, "high": 4, "medium": 4, "low": 0}
    findings_by_category: dict = field(default_factory=dict) # {"security": 2, "compounding": 4, "business": 2, "operational": 3}
    
    # Anti-pattern flags — boolean markers for common dangerous patterns
    # Powers: "73% of projects have at least one unguarded data→external path"
    has_unguarded_data_external: bool = False        # STRATUM-001 fired
    has_destructive_no_gate: bool = False             # STRATUM-002 fired
    has_blast_radius_3_plus: bool = False             # Any CR05 fired
    has_control_bypass: bool = False                  # CR06 fired
    has_unvalidated_chain: bool = False               # CR02 fired
    has_shared_tool_bridge: bool = False              # CR01 fired
    has_no_error_handling: bool = False               # STRATUM-008 fired
    has_no_timeout: bool = False                      # STRATUM-009 fired
    has_no_checkpointing: bool = False                # STRATUM-010 fired
    has_no_audit_trail: bool = False                  # BR03 fired
    has_unreviewed_external_comms: bool = False       # BR01 fired
    has_no_cost_controls: bool = False                # OP02 fired
    
    # Incident pattern matching
    incident_matches: list = field(default_factory=list)     # [{"id": "ECHOLEAK-2025", "confidence": 1.0}, ...]
    incident_match_count: int = 0
    matches_echoleak: bool = False          # Specific flag for the most common/alarming pattern
    matches_any_breach: bool = False        # Any incident match with confidence >= 0.75

    # ─── BLAST RADIUS ───────────────────────────────────────────
    # Powers: "your median blast radius is 4.1, industry is 2.3"
    
    blast_radii: list = field(default_factory=list)
    # Each entry: {"tool_category": "web_scraping", "agent_count": 4, "external_count": 2, "crew_hash": "a1b2c3"}
    # Tool name included (open source), crew name hashed
    
    blast_radius_count: int = 0             # Total blast radius instances
    max_blast_radius: int = 0               # Largest single fan-out
    total_blast_surface: int = 0            # Sum of all agent_counts — total exposure
    blast_radius_distribution: dict = field(default_factory=dict)  # {"2": 4, "3": 2, "4": 1}
    
    # ─── CONTROL MATURITY ───────────────────────────────────────
    # Powers: "adding HITL reduces risk by avg 28 points"
    # Powers: maturity benchmarking, compliance assessment
    
    guardrail_count: int = 0
    guardrail_types: dict = field(default_factory=dict)     # {"validation": 13, "hitl": 0, "output_filter": 0, "rate_limit": 0}
    guardrail_linked_count: int = 0                          # Guardrails with non-empty covers_tools
    guardrail_coverage_ratio: float = 0.0                    # linked / total guardrails
    
    control_coverage_pct: float = 0.0       # Edges with controls / controllable edges
    
    has_hitl: bool = False                  # Any human-in-the-loop gate anywhere
    has_structured_output: bool = False     # Any output_pydantic or structured validation
    has_checkpointing: bool = False
    checkpoint_type: str = "none"           # "none", "memory", "durable"
    has_observability: bool = False          # Langfuse, LangSmith, OpenTelemetry, etc.
    has_rate_limiting: bool = False          # max_rpm, max_iterations, token budgets
    has_error_handling: bool = False         # Any error handling on external calls
    error_handling_ratio: float = 0.0       # Calls with error handling / total external calls
    has_input_validation: bool = False       # Any input validation on tools
    has_output_filtering: bool = False       # Any output filtering/sanitization
    
    # Composite maturity score (0-100) derived from control signals
    # Formula: weighted sum of control booleans
    # This is what enterprise dashboards show as "AI Governance Maturity"
    maturity_score: int = 0
    maturity_level: str = ""                # "none" (0-20), "basic" (21-40), "developing" (41-60), "established" (61-80), "advanced" (81-100)
    
    # ─── DATA FLOW ──────────────────────────────────────────────
    # Powers: compliance mapping, data sensitivity analysis
    
    sensitive_data_types: list = field(default_factory=list) # ["personal", "financial", "credentials", "health", "internal"]
    has_pii_flow: bool = False              # PII enters and flows to external
    has_financial_flow: bool = False
    has_credential_flow: bool = False
    
    uncontrolled_path_count: int = 0        # Sensitive data → external with no control
    max_path_hops: int = 0                  # Longest uncontrolled path
    trust_boundary_crossings: int = 0
    downward_crossings: int = 0             # Internal → external (riskier direction)
    
    # Path patterns — which specific data flow anti-patterns exist?
    has_inbox_to_outbound: bool = False      # Email read → email send (EchoLeak pattern)
    has_scrape_to_action: bool = False       # Web scrape → tool execution (Gordon pattern)
    has_db_to_external: bool = False         # Database read → external send
    has_file_to_external: bool = False       # File read → external send

    # ─── REGULATORY EXPOSURE ────────────────────────────────────
    # Powers: compliance gap reports, regulatory risk scoring
    
    applicable_regulations: list = field(default_factory=list)
    # ["EU_AI_ACT", "GDPR", "NIST_AI_RMF", "SOC2", "ISO27001"]
    
    eu_ai_act_risk_level: str = ""          # "unacceptable", "high", "limited", "minimal", "unknown"
    eu_ai_act_articles: list = field(default_factory=list)   # ["Art.9", "Art.14", "Art.15"]
    eu_ai_act_gap_count: int = 0            # Number of article requirements not met
    
    gdpr_relevant: bool = False             # Processes personal data
    gdpr_articles: list = field(default_factory=list)        # ["Art.35", "Art.22"]
    
    nist_ai_rmf_functions: list = field(default_factory=list) # ["MAP", "MEASURE", "MANAGE", "GOVERN"]
    
    compliance_gap_count: int = 0           # Total gaps across all frameworks
    
    # ─── GRAPH TOPOLOGY ─────────────────────────────────────────
    # Powers: architecture pattern matching, anomaly detection
    
    node_count: int = 0
    edge_count: int = 0
    edge_density: float = 0.0
    agent_to_agent_edges: int = 0           # feeds_into + delegates_to count
    guardrail_edges: int = 0                # gated_by + filtered_by count
    
    # Connectivity metrics — how "coupled" is the agent system?
    avg_node_degree: float = 0.0            # Average edges per node
    max_node_degree: int = 0                # Most connected node
    isolated_agent_count: int = 0           # Agents with no edges (disconnected)
    
    # ─── DELTA (from previous scan of same topology_signature) ──
    # Powers: trend tracking, "are we getting better or worse?"
    
    has_previous_scan: bool = False
    previous_risk_score: int = 0
    risk_score_delta: int = 0               # Positive = worse, negative = better
    new_finding_ids: list = field(default_factory=list)      # Findings that appeared since last scan
    resolved_finding_ids: list = field(default_factory=list) # Findings that disappeared
    new_finding_count: int = 0
    resolved_finding_count: int = 0
    maturity_score_delta: int = 0

    # ─── WHAT-IF SIGNALS ────────────────────────────────────────
    # Powers: "if you add HITL, your score drops by X"
    # Computed by the scanner: for each missing control, estimate impact
    
    # Each entry: {"control": "hitl_on_outbound", "findings_suppressed": ["STRATUM-001", "STRATUM-BR01"], "score_reduction": 34}
    what_if_controls: list = field(default_factory=list)
    
    # Top recommended action and its estimated impact
    top_recommendation: str = ""            # "add_hitl_email_outbound"
    top_recommendation_impact: int = 0      # Estimated risk score reduction
```

### Layer 2: RepoContext (GitHub scraper adds this)

```python
@dataclass
class RepoContext:
    """
    Repository metadata from GitHub. NOT captured by the scanner.
    Added by the batch scan pipeline for public repos.
    Enterprise customers provide equivalent context through their own metadata.
    """
    
    # ─── REPO IDENTITY ──────────────────────────────────────────
    repo_hash: str = ""                 # SHA256 of owner/repo — anonymized
    platform: str = "github"            # "github", "gitlab", "bitbucket"
    
    # ─── POPULARITY (proxy for adoption/impact) ─────────────────
    stars: int = 0
    forks: int = 0
    watchers: int = 0
    open_issues: int = 0
    
    # ─── ACTIVITY ───────────────────────────────────────────────
    created_at: str = ""                # ISO 8601
    last_commit_at: str = ""
    days_since_last_commit: int = 0
    commit_count_90d: int = 0           # Commits in last 90 days
    contributor_count: int = 0
    is_archived: bool = False
    is_active: bool = False             # Commit in last 30 days
    
    # ─── STRUCTURE ──────────────────────────────────────────────
    primary_language: str = ""          # "Python", "TypeScript"
    total_files: int = 0
    total_lines: int = 0
    has_tests: bool = False             # tests/ or test_ files exist
    has_ci: bool = False                # .github/workflows, .gitlab-ci.yml, etc.
    has_dockerfile: bool = False
    has_requirements_txt: bool = False
    has_pyproject_toml: bool = False
    
    # ─── DOMAIN INFERENCE ───────────────────────────────────────
    # Inferred from README, repo name, description, dependencies
    # Powers: vertical benchmarking ("fintech agents vs. HR agents")
    
    domain_hint: str = ""               # "finance", "hr", "devops", "marketing", "customer_support", "research", "general"
    domain_confidence: float = 0.0
    
    # Keywords found in README/description that suggest domain
    domain_signals: list = field(default_factory=list)  # ["trading", "portfolio", "SEC", "financial"]
    
    # ─── DEPENDENCY VERSIONS ────────────────────────────────────
    # Powers: "projects on crewai < 0.50 have 2x more findings"
    
    dependency_versions: dict = field(default_factory=dict)  # {"crewai": "0.51.0", "langchain-core": "0.1.20"}
    outdated_dependencies: int = 0      # Count of deps with known newer versions
    
    # ─── README ANALYSIS ────────────────────────────────────────
    has_readme: bool = False
    readme_mentions_security: bool = False
    readme_mentions_production: bool = False
    readme_length: int = 0              # Rough proxy for documentation quality
```

---

## HOW EACH ENTERPRISE SLIDE IS POWERED

### Slide 1: "7 of your projects match breach architectures"

**Query:** For each project in customer fleet, check `incident_matches` and `matches_any_breach`.

**Benchmark context:** "Across 52,000 projects, 23% match at least one breach architecture. In fintech, it's 31%."

**Required fields:** `incident_matches`, `matches_echoleak`, `matches_any_breach`, `tool_names`, `external_services`, `has_inbox_to_outbound`, `has_scrape_to_action`

**Why current telemetry can't do this:** No `incident_matches` list, no `tool_names`, no path pattern flags.

### Slide 2: "Your blast radius is 94th percentile"

**Query:** Compare customer's `max_blast_radius` and `blast_radius_distribution` against the ecosystem, filtered by `domain_hint` and `archetype`.

**Required fields:** `blast_radii` (per-crew, with tool category), `max_blast_radius`, `blast_radius_distribution`, `domain_hint` (from RepoContext), `archetype`

**Why current telemetry can't do this:** `max_blast_radius` exists but is computed globally (inflated). No per-crew breakdown. No tool category in blast_radii. No domain signal for cohort filtering.

### Slide 3: "Add HITL to these 3 tasks, risk drops 34%"

**Query:** Read `what_if_controls` for each project. Aggregate across fleet. Rank by `score_reduction`.

**Cross-reference:** For the recommended control, query the ecosystem: "across projects that added HITL on email-outbound paths, what was the average risk score change?"

This requires matching projects where `has_hitl: false` → `has_hitl: true` between scans (delta tracking).

**Required fields:** `what_if_controls`, `top_recommendation`, `top_recommendation_impact`, `risk_score_delta`, `maturity_score_delta`

**Why current telemetry can't do this:** None of these fields exist. No what-if computation. No delta tracking.

### Slide 4: "Here's your EU AI Act gap report"

**Query:** Filter customer projects by `gdpr_relevant: true` or `eu_ai_act_risk_level: "high"`. For each, list `eu_ai_act_articles` and `eu_ai_act_gap_count`.

**Benchmark context:** "Across fintech agent projects, the median EU AI Act gap count is 3.2. Your fleet has 5.1."

**Required fields:** `applicable_regulations`, `eu_ai_act_risk_level`, `eu_ai_act_articles`, `eu_ai_act_gap_count`, `gdpr_relevant`, `gdpr_articles`, `compliance_gap_count`

**Why current telemetry can't do this:** Only `regulatory_frameworks` as a flat list in risk_surface. No article-level mapping. No gap counting. No risk level classification.

### Slide 5: "Team Alpha improved 22%, Team Beta got worse"

**Query:** For each `topology_signature`, compare `risk_score` and `maturity_score` across scans. Compute `risk_score_delta`, `new_finding_count`, `resolved_finding_count`.

**Required fields:** `scan_timestamp`, `topology_signature`, `has_previous_scan`, `risk_score_delta`, `new_finding_ids`, `resolved_finding_ids`, `maturity_score_delta`

**Why current telemetry can't do this:** No timestamp in telemetry. No delta fields. Topology signature exists but diff data isn't in the profile.

---

## WHAT-IF COMPUTATION

This is the single most valuable new computation in the scanner. It answers: "if this control existed, which findings would not fire, and by how much would the risk score drop?"

```python
def compute_what_if_controls(findings, capabilities, guardrails, graph) -> list[dict]:
    """
    For each control that could be added, compute which findings it would suppress
    and the resulting risk score reduction.
    
    Returns list of:
    {
        "control": "hitl_on_outbound",
        "description": "Add human_input=True on tasks with outbound external actions",
        "findings_suppressed": ["STRATUM-001", "STRATUM-BR01"],
        "severity_suppressed": {"critical": 1, "high": 1},
        "score_reduction": 34,
        "effort": "low",
        "crew_hashes": ["a1b2", "c3d4"]
    }
    """
    what_ifs = []
    
    # What-if: Add HITL on all outbound paths
    hitl_suppresses = []
    for f in findings:
        if f.quick_fix_type == "add_hitl" or f.id in ("STRATUM-001", "STRATUM-BR01", "STRATUM-002"):
            hitl_suppresses.append(f)
    
    if hitl_suppresses:
        score_reduction = sum(
            25 if f.severity == "CRITICAL" else
            15 if f.severity == "HIGH" else
            8 if f.severity == "MEDIUM" else 3
            for f in hitl_suppresses
        )
        what_ifs.append({
            "control": "hitl_on_outbound",
            "description": "Add human_input=True on tasks with outbound external actions",
            "findings_suppressed": [f.id for f in hitl_suppresses],
            "severity_suppressed": _count_by_severity(hitl_suppresses),
            "score_reduction": score_reduction,
            "effort": "low"
        })
    
    # What-if: Add structured output validation between agent steps
    validation_suppresses = []
    for f in findings:
        if f.id in ("STRATUM-CR02", "STRATUM-BR04"):
            validation_suppresses.append(f)
    
    if validation_suppresses:
        score_reduction = sum(
            25 if f.severity == "CRITICAL" else
            15 if f.severity == "HIGH" else
            8 if f.severity == "MEDIUM" else 3
            for f in validation_suppresses
        )
        what_ifs.append({
            "control": "structured_output_validation",
            "description": "Add output_pydantic validation on tasks in sequential chains",
            "findings_suppressed": [f.id for f in validation_suppresses],
            "severity_suppressed": _count_by_severity(validation_suppresses),
            "score_reduction": score_reduction,
            "effort": "low"
        })
    
    # What-if: Add error handling on all external calls
    error_suppresses = [f for f in findings if f.id in ("STRATUM-008",)]
    if error_suppresses:
        what_ifs.append({
            "control": "error_handling",
            "description": "Add try/except with graceful degradation on external calls",
            "findings_suppressed": [f.id for f in error_suppresses],
            "severity_suppressed": _count_by_severity(error_suppresses),
            "score_reduction": sum(8 for _ in error_suppresses),
            "effort": "med"
        })
    
    # What-if: Add input validation on shared tools
    shared_tool_suppresses = [f for f in findings if f.id.startswith("STRATUM-CR05") or f.id == "STRATUM-CR01"]
    if shared_tool_suppresses:
        score_reduction = sum(
            25 if f.severity == "CRITICAL" else 15 if f.severity == "HIGH" else 8
            for f in shared_tool_suppresses
        )
        what_ifs.append({
            "control": "shared_tool_validation",
            "description": "Add input validation on tools shared by 3+ agents",
            "findings_suppressed": [f.id for f in shared_tool_suppresses],
            "severity_suppressed": _count_by_severity(shared_tool_suppresses),
            "score_reduction": score_reduction,
            "effort": "med"
        })
    
    # What-if: Add observability
    obs_suppresses = [f for f in findings if f.id in ("TELEMETRY-003", "STRATUM-BR03")]
    if obs_suppresses:
        what_ifs.append({
            "control": "observability",
            "description": "Add Langfuse, LangSmith, or OpenTelemetry tracing",
            "findings_suppressed": [f.id for f in obs_suppresses],
            "severity_suppressed": _count_by_severity(obs_suppresses),
            "score_reduction": sum(8 if f.severity == "MEDIUM" else 3 for f in obs_suppresses),
            "effort": "low"
        })
    
    # Sort by score_reduction descending — highest impact first
    what_ifs.sort(key=lambda x: -x["score_reduction"])
    
    return what_ifs
```

---

## MATURITY SCORE COMPUTATION

A composite score that gives enterprises a single number for "how governed are your agents?"

```python
def compute_maturity_score(profile: ScanProfile) -> tuple[int, str]:
    """
    Weighted composite of control signals.
    Returns (score 0-100, level label).
    
    Weights reflect what actually reduces risk based on the ecosystem data.
    Initially set by judgment; recalibrated once N > 5000 using actual
    risk score correlations.
    """
    score = 0
    
    # Human oversight (most impactful)
    if profile.has_hitl:
        score += 25
    
    # Output validation (prevents hallucination propagation)
    if profile.has_structured_output:
        score += 15
    
    # Observability (can't fix what you can't see)
    if profile.has_observability:
        score += 15
    
    # Error handling (resilience)
    if profile.has_error_handling:
        score += 10
    elif profile.error_handling_ratio > 0:
        score += int(10 * profile.error_handling_ratio)
    
    # Checkpointing (recovery)
    if profile.checkpoint_type == "durable":
        score += 10
    elif profile.has_checkpointing:
        score += 5
    
    # Input validation on tools
    if profile.has_input_validation:
        score += 10
    
    # Rate limiting (cost control, runaway prevention)
    if profile.has_rate_limiting:
        score += 5
    
    # Output filtering (content safety)
    if profile.has_output_filtering:
        score += 5
    
    # Guardrail coverage (are guardrails actually connected?)
    if profile.guardrail_coverage_ratio > 0.5:
        score += 5
    elif profile.guardrail_coverage_ratio > 0:
        score += 2
    
    score = min(score, 100)
    
    if score <= 20:
        level = "none"
    elif score <= 40:
        level = "basic"
    elif score <= 60:
        level = "developing"
    elif score <= 80:
        level = "established"
    else:
        level = "advanced"
    
    return score, level
```

---

## REGULATORY EXPOSURE COMPUTATION

```python
def compute_regulatory_exposure(profile: ScanProfile) -> dict:
    """
    Map data flows and control states to specific regulatory requirements.
    Returns populated regulatory fields for the profile.
    """
    result = {
        "applicable_regulations": [],
        "eu_ai_act_risk_level": "unknown",
        "eu_ai_act_articles": [],
        "eu_ai_act_gap_count": 0,
        "gdpr_relevant": False,
        "gdpr_articles": [],
        "nist_ai_rmf_functions": [],
        "compliance_gap_count": 0,
    }
    
    # ── EU AI Act ──
    
    # Risk level classification (simplified — real classification requires domain context)
    if profile.has_financial_tools or profile.has_credential_flow:
        result["eu_ai_act_risk_level"] = "high"
    elif profile.has_pii_flow:
        result["eu_ai_act_risk_level"] = "limited"
    else:
        result["eu_ai_act_risk_level"] = "minimal"
    
    gaps = 0
    
    # Art. 9 — Risk management system
    result["eu_ai_act_articles"].append("Art.9")
    if not profile.has_observability and not profile.has_structured_output:
        gaps += 1  # No systematic risk identification
    
    # Art. 14 — Human oversight
    result["eu_ai_act_articles"].append("Art.14")
    if not profile.has_hitl:
        gaps += 1
    
    # Art. 15 — Accuracy, robustness, cybersecurity
    result["eu_ai_act_articles"].append("Art.15")
    if profile.has_no_error_handling or not profile.has_input_validation:
        gaps += 1
    
    # Art. 13 — Transparency and information to deployers
    if not profile.has_observability:
        result["eu_ai_act_articles"].append("Art.13")
        gaps += 1
    
    # Art. 12 — Record-keeping
    if profile.has_no_audit_trail:
        result["eu_ai_act_articles"].append("Art.12")
        gaps += 1
    
    result["eu_ai_act_gap_count"] = gaps
    result["applicable_regulations"].append("EU_AI_ACT")
    
    # ── GDPR ──
    
    if profile.has_pii_flow:
        result["gdpr_relevant"] = True
        result["applicable_regulations"].append("GDPR")
        
        # Art. 35 — DPIA required for high-risk processing
        if profile.uncontrolled_path_count > 0:
            result["gdpr_articles"].append("Art.35")
            gaps += 1
        
        # Art. 22 — Automated decision-making
        if not profile.has_hitl:
            result["gdpr_articles"].append("Art.22")
            gaps += 1
    
    # ── NIST AI RMF ──
    
    result["applicable_regulations"].append("NIST_AI_RMF")
    
    if profile.has_observability:
        result["nist_ai_rmf_functions"].append("MEASURE")
    if profile.has_hitl or profile.has_structured_output:
        result["nist_ai_rmf_functions"].append("MANAGE")
    if profile.maturity_score > 40:
        result["nist_ai_rmf_functions"].append("GOVERN")
    # MAP is always applicable
    result["nist_ai_rmf_functions"].append("MAP")
    
    result["compliance_gap_count"] = gaps
    
    return result
```

---

## TOOL CATEGORIZATION

The scanner already detects tool names. We need to categorize them for cohort analysis.

```python
TOOL_CATEGORIES = {
    # Search & Research
    "search": ["SerperDevTool", "TavilySearchResults", "WebsiteSearchTool", "web_search_tool", "seper_dev_tool", "DuckDuckGoSearchRun"],
    
    # Email
    "email": ["GmailToolkit", "GmailGetThread", "GmailSendMessage", "GmailCreateDraft", "OutlookToolkit"],
    
    # Messaging
    "messaging": ["slack_sdk", "SlackToolkit", "TeamsToolkit", "DiscordToolkit"],
    
    # Web Scraping
    "scraping": ["ScrapeWebsiteTool", "requests", "BeautifulSoup", "SeleniumTool"],
    
    # File System
    "file": ["FileReadTool", "FileManagementToolkit", "file_read_tool", "FileWriteTool", "DirectoryReadTool"],
    
    # Data / Database
    "data": ["CSVSearchTool", "TXTSearchTool", "RagTool", "PDFSearchTool", "JSONSearchTool", "ChromaDB", "PGSearchTool"],
    
    # Financial
    "financial": ["SEC10KTool", "SEC10QTool", "CalculatorTool", "YFinanceTool", "AlphaVantageTool"],
    
    # Code Execution
    "code_exec": ["CodeInterpreterTool", "PythonREPLTool", "BashTool", "exec"],
    
    # Social / Publishing
    "social": ["LinkedInTool", "TwitterTool", "InstagramTool"],
    
    # Project Management
    "project": ["TrelloTool", "JiraTool", "AsanaTool", "NotionTool"],
    
    # Validation / Internal
    "validation": ["CharacterCounterTool", "markdown_validation_tool", "SchemaTool"],
}

def categorize_tools(tool_names: list) -> dict:
    """Returns {"search": 3, "email": 2, ...}"""
    categories = {}
    for tool in tool_names:
        for category, known_tools in TOOL_CATEGORIES.items():
            if any(known in tool for known in known_tools):
                categories[category] = categories.get(category, 0) + 1
                break
        else:
            categories["other"] = categories.get("other", 0) + 1
    return categories
```

---

## DOMAIN INFERENCE (for RepoContext)

```python
DOMAIN_KEYWORDS = {
    "finance": ["trading", "portfolio", "SEC", "financial", "investment", "stock", "fund", "banking", "fintech", "payment", "accounting"],
    "hr": ["recruitment", "hiring", "candidate", "resume", "CV", "job posting", "onboarding", "employee", "HR"],
    "marketing": ["marketing", "campaign", "content", "SEO", "social media", "brand", "advertising", "lead gen"],
    "customer_support": ["support", "ticket", "helpdesk", "customer service", "chatbot", "FAQ", "complaint"],
    "devops": ["deployment", "CI/CD", "monitoring", "infrastructure", "Docker", "Kubernetes", "DevOps"],
    "research": ["research", "analysis", "paper", "academic", "literature", "survey"],
    "legal": ["legal", "contract", "compliance", "regulation", "policy", "terms"],
    "healthcare": ["patient", "diagnosis", "medical", "health", "clinical", "HIPAA"],
}

def infer_domain(readme_text: str, repo_name: str, description: str) -> tuple[str, float, list]:
    """
    Returns (domain, confidence, matching_signals).
    """
    text = f"{readme_text} {repo_name} {description}".lower()
    
    scores = {}
    signals = {}
    for domain, keywords in DOMAIN_KEYWORDS.items():
        matches = [kw for kw in keywords if kw.lower() in text]
        if matches:
            scores[domain] = len(matches)
            signals[domain] = matches
    
    if not scores:
        return ("general", 0.0, [])
    
    best = max(scores, key=scores.get)
    confidence = min(1.0, scores[best] / 3.0)
    return (best, confidence, signals[best])
```

---

## POPULATION LOGIC — BUILDING THE PROFILE

```python
def build_scan_profile(
    scan_result,
    graph,
    crews,
    blast_radii,
    findings,
    signals,
    capabilities,
    guardrails,
    agents,
    previous_profile=None     # For delta computation
) -> ScanProfile:
    
    p = ScanProfile()
    
    # ── Identity ──
    p.scan_id = scan_result.scan_id
    p.topology_signature = scan_result.telemetry_profile.get("topology_signature", "")
    p.scan_timestamp = scan_result.timestamp
    p.scanner_version = "0.2.0"
    
    # ── Architecture ──
    p.archetype = scan_result.telemetry_profile.get("archetype", "")
    p.archetype_confidence = scan_result.telemetry_profile.get("archetype_confidence", 0.0)
    p.frameworks = scan_result.detected_frameworks
    p.framework_versions = _detect_framework_versions(scan_result.directory)  # NEW: parse pyproject.toml/requirements.txt
    p.agent_count = len(agents)
    p.crew_count = len(crews)
    p.files_scanned = scan_result.files_scanned
    p.is_monorepo = len(crews) > 3 and _has_multiple_project_dirs(crews)
    
    p.crew_sizes = sorted([len(c.agent_names) for c in crews], reverse=True)
    p.crew_process_types = _count_field(crews, "process_type")
    p.max_chain_depth = _compute_max_chain([e for e in graph["edges"] if e["type"] == "feeds_into"])
    p.avg_crew_size = sum(p.crew_sizes) / len(p.crew_sizes) if p.crew_sizes else 0
    p.has_hierarchical_crew = any(c.get("process_type") == "hierarchical" for c in crews)
    p.has_delegation = any(c.get("delegation_enabled") or c.get("has_manager") for c in crews)
    
    # ── Tool inventory ──
    all_tools = set()
    tool_assignments = 0
    for a in agents:
        for t in a.get("tool_names", []):
            all_tools.add(t)
            tool_assignments += 1
    
    p.tool_names = sorted(all_tools)
    p.tool_count = len(all_tools)
    p.tool_categories = categorize_tools(list(all_tools))
    p.libraries = sorted(set(c.library for c in capabilities if c.library))
    p.capability_counts = {
        "outbound": scan_result.outbound_count,
        "data_access": scan_result.data_access_count,
        "code_exec": scan_result.code_exec_count,
        "destructive": scan_result.destructive_count,
        "financial": scan_result.financial_count,
    }
    p.outbound_to_data_ratio = round(
        scan_result.outbound_count / max(scan_result.data_access_count, 1), 2
    )
    p.tool_reuse_ratio = round(len(all_tools) / max(tool_assignments, 1), 2)
    
    # Per-crew tool sharing
    max_sharing = 0
    tools_shared_3 = 0
    for crew in crews:
        crew_agents = set(crew.agent_names)
        tool_agent_count = {}
        for a in agents:
            if a.name in crew_agents:
                for t in a.get("tool_names", []):
                    tool_agent_count[t] = tool_agent_count.get(t, 0) + 1
        for t, count in tool_agent_count.items():
            max_sharing = max(max_sharing, count)
            if count >= 3:
                tools_shared_3 += 1
    p.max_tool_sharing = max_sharing
    p.tools_shared_by_3_plus = tools_shared_3
    
    # ── External services ──
    p.external_services = sorted(set(
        n["label"] for n in graph["nodes"] if n["type"] == "external"
    ))
    p.external_service_count = len(p.external_services)
    p.data_sources = sorted(set(
        n["label"] for n in graph["nodes"] if n["type"] == "data_store"
    ))
    p.data_source_count = len(p.data_sources)
    
    # Service pattern flags
    p.has_email_integration = any("gmail" in t.lower() or "outlook" in t.lower() for t in all_tools)
    p.has_messaging_integration = any("slack" in l.lower() or "teams" in l.lower() for l in p.libraries)
    p.has_web_scraping = any("scrape" in t.lower() or t == "requests" for t in all_tools) or "requests" in p.libraries
    p.has_database_integration = any("pg" in t.lower() or "mongo" in t.lower() or "chroma" in t.lower() for t in all_tools)
    p.has_file_system_access = any("file" in t.lower() for t in all_tools)
    p.has_financial_tools = any("sec" in t.lower() or "calculator" in t.lower() or "finance" in t.lower() for t in all_tools)
    p.has_code_execution = scan_result.code_exec_count > 0
    
    # ── Risk profile ──
    all_findings = findings + signals  # Combine top_paths and signals
    p.risk_score = scan_result.risk_score
    p.risk_score_breakdown = _compute_score_breakdown(all_findings, guardrails)
    p.risk_scores_per_crew = sorted([
        _crew_score(c, all_findings) for c in crews if _crew_score(c, all_findings) > 0
    ], reverse=True)
    
    p.finding_ids = [f.id for f in all_findings]
    p.finding_count = len(all_findings)
    p.findings_by_severity = _count_field(all_findings, "severity")
    p.findings_by_category = _count_field(all_findings, "category")
    
    # Anti-pattern flags
    finding_id_set = set(p.finding_ids)
    p.has_unguarded_data_external = "STRATUM-001" in finding_id_set
    p.has_destructive_no_gate = "STRATUM-002" in finding_id_set
    p.has_blast_radius_3_plus = any(fid.startswith("STRATUM-CR05") for fid in finding_id_set)
    p.has_control_bypass = "STRATUM-CR06" in finding_id_set
    p.has_unvalidated_chain = "STRATUM-CR02" in finding_id_set
    p.has_shared_tool_bridge = "STRATUM-CR01" in finding_id_set
    p.has_no_error_handling = "STRATUM-008" in finding_id_set
    p.has_no_timeout = "STRATUM-009" in finding_id_set
    p.has_no_checkpointing = "STRATUM-010" in finding_id_set
    p.has_no_audit_trail = "STRATUM-BR03" in finding_id_set
    p.has_unreviewed_external_comms = "STRATUM-BR01" in finding_id_set
    p.has_no_cost_controls = "STRATUM-OP02" in finding_id_set
    
    # Incident matching
    p.incident_matches = [
        {"id": m.incident_id, "confidence": m.confidence}
        for m in scan_result.incident_matches
    ]
    p.incident_match_count = len(p.incident_matches)
    p.matches_echoleak = any(m.incident_id == "ECHOLEAK-2025" and m.confidence >= 0.75 for m in scan_result.incident_matches)
    p.matches_any_breach = any(m.confidence >= 0.75 for m in scan_result.incident_matches)
    
    # ── Blast radius ──
    p.blast_radii = [
        {
            "tool": br.source_label,
            "tool_category": _categorize_single_tool(br.source_label),
            "agent_count": br.agent_count,
            "external_count": br.external_count,
            "crew_hash": hashlib.sha256(br.crew_name.encode()).hexdigest()[:8] if br.crew_name else ""
        }
        for br in blast_radii
    ]
    p.blast_radius_count = len(blast_radii)
    p.max_blast_radius = max((br.agent_count for br in blast_radii), default=0)
    p.total_blast_surface = sum(br.agent_count for br in blast_radii)
    br_counts = [br.agent_count for br in blast_radii]
    p.blast_radius_distribution = {str(k): br_counts.count(k) for k in set(br_counts)} if br_counts else {}
    
    # ── Control maturity ──
    p.guardrail_count = len(guardrails)
    p.guardrail_types = _count_field(guardrails, "kind")
    p.guardrail_linked_count = sum(1 for g in guardrails if g.covers_tools)
    p.guardrail_coverage_ratio = round(p.guardrail_linked_count / max(p.guardrail_count, 1), 2)
    
    p.control_coverage_pct = graph.get("risk_surface", {}).get("control_coverage_pct", 0.0)
    p.has_hitl = any(g.kind == "hitl" for g in guardrails)
    p.has_structured_output = any("output_pydantic" in g.detail for g in guardrails)
    p.has_checkpointing = scan_result.checkpoint_type != "none"
    p.checkpoint_type = scan_result.checkpoint_type
    p.has_observability = "TELEMETRY-003" not in finding_id_set
    p.has_rate_limiting = not p.has_no_cost_controls
    p.has_error_handling = any(c.has_error_handling for c in capabilities)
    handled = sum(1 for c in capabilities if c.has_error_handling)
    p.error_handling_ratio = round(handled / max(len(capabilities), 1), 2)
    p.has_input_validation = any(c.has_input_validation for c in capabilities)
    p.has_output_filtering = any(g.kind == "output_filter" for g in guardrails)
    
    p.maturity_score, p.maturity_level = compute_maturity_score(p)
    
    # ── Data flow ──
    surface = graph.get("risk_surface", {})
    p.sensitive_data_types = surface.get("sensitive_data_types", [])
    p.has_pii_flow = "personal" in p.sensitive_data_types and p.uncontrolled_path_count > 0
    p.has_financial_flow = "financial" in p.sensitive_data_types
    p.has_credential_flow = "credentials" in p.sensitive_data_types
    p.uncontrolled_path_count = surface.get("uncontrolled_path_count", 0)
    p.max_path_hops = surface.get("max_path_hops", 0)
    p.trust_boundary_crossings = surface.get("trust_boundary_crossings", 0)
    p.downward_crossings = surface.get("downward_crossings", 0)
    
    # Path pattern flags
    p.has_inbox_to_outbound = p.has_email_integration and "ext_gmail_outbound" in str(graph.get("nodes", []))
    p.has_scrape_to_action = p.has_web_scraping and any(
        e["type"] == "sends_to" for e in graph.get("edges", [])
        if "scrape" in e.get("source", "").lower()
    )
    p.has_db_to_external = p.has_database_integration and p.uncontrolled_path_count > 0
    p.has_file_to_external = p.has_file_system_access and any(
        "file" in e.get("source", "").lower() and e["type"] == "shares_with"
        for e in graph.get("edges", [])
    )
    
    # ── Regulatory ──
    reg = compute_regulatory_exposure(p)
    p.applicable_regulations = reg["applicable_regulations"]
    p.eu_ai_act_risk_level = reg["eu_ai_act_risk_level"]
    p.eu_ai_act_articles = reg["eu_ai_act_articles"]
    p.eu_ai_act_gap_count = reg["eu_ai_act_gap_count"]
    p.gdpr_relevant = reg["gdpr_relevant"]
    p.gdpr_articles = reg["gdpr_articles"]
    p.nist_ai_rmf_functions = reg["nist_ai_rmf_functions"]
    p.compliance_gap_count = reg["compliance_gap_count"]
    
    # ── Graph topology ──
    p.node_count = len(graph.get("nodes", []))
    p.edge_count = len(graph.get("edges", []))
    n = p.node_count
    p.edge_density = round(p.edge_count / (n * (n - 1)), 4) if n > 1 else 0
    p.agent_to_agent_edges = sum(1 for e in graph.get("edges", []) if e["type"] == "feeds_into")
    p.guardrail_edges = sum(1 for e in graph.get("edges", []) if e["type"] in ("gated_by", "filtered_by"))
    
    degrees = {}
    for e in graph.get("edges", []):
        degrees[e["source"]] = degrees.get(e["source"], 0) + 1
        degrees[e["target"]] = degrees.get(e["target"], 0) + 1
    p.avg_node_degree = round(sum(degrees.values()) / max(len(degrees), 1), 2)
    p.max_node_degree = max(degrees.values(), default=0)
    agent_node_ids = set(n["id"] for n in graph.get("nodes", []) if n["type"] == "agent")
    connected_agents = set()
    for e in graph.get("edges", []):
        if e["source"] in agent_node_ids:
            connected_agents.add(e["source"])
        if e["target"] in agent_node_ids:
            connected_agents.add(e["target"])
    p.isolated_agent_count = len(agent_node_ids - connected_agents)
    
    # ── Delta ──
    if previous_profile:
        p.has_previous_scan = True
        p.previous_risk_score = previous_profile.risk_score
        p.risk_score_delta = p.risk_score - previous_profile.risk_score
        prev_ids = set(previous_profile.finding_ids)
        curr_ids = set(p.finding_ids)
        p.new_finding_ids = sorted(curr_ids - prev_ids)
        p.resolved_finding_ids = sorted(prev_ids - curr_ids)
        p.new_finding_count = len(p.new_finding_ids)
        p.resolved_finding_count = len(p.resolved_finding_ids)
        p.maturity_score_delta = p.maturity_score - previous_profile.maturity_score
    
    # ── What-if ──
    p.what_if_controls = compute_what_if_controls(all_findings, capabilities, guardrails, graph)
    if p.what_if_controls:
        p.top_recommendation = p.what_if_controls[0]["control"]
        p.top_recommendation_impact = p.what_if_controls[0]["score_reduction"]
    
    return p
```

---

## THE GITHUB BATCH SCAN PIPELINE

This runs locally on a server. It's a script, not part of the scanner itself.

```python
"""
batch_scan.py — Scan every agent project on GitHub

Usage:
    python batch_scan.py --query "crewai" --max-repos 10000 --output ./scans/
    python batch_scan.py --query "langchain agent" --max-repos 10000 --output ./scans/
    python batch_scan.py --query "autogen" --max-repos 5000 --output ./scans/
    python batch_scan.py --query "langgraph" --max-repos 5000 --output ./scans/
"""

SEARCH_QUERIES = [
    # Framework-specific
    "crewai",
    "crewai crew",
    "langchain agent tool",
    "langgraph",
    "autogen agent",
    "langchain ReAct agent",
    
    # Pattern-specific
    "AI agent tool use",
    "multi agent system python",
    "agent orchestration",
    "agentic workflow",
    
    # Tool-specific (high-risk patterns)
    "GmailToolkit langchain",
    "slack agent tool",
    "agent file management",
    "agent web scraper",
]

def scan_github():
    for query in SEARCH_QUERIES:
        repos = github_search(query, language="Python", sort="stars")
        
        for repo in repos:
            # Skip if already scanned (by repo_hash)
            if already_scanned(repo):
                continue
            
            # Clone
            clone_dir = clone_repo(repo)
            
            # Scan
            scan_result = run_stratum_scan(clone_dir)
            
            # Build profiles
            scan_profile = build_scan_profile(scan_result, ...)
            repo_context = build_repo_context(repo, clone_dir)
            
            # Store
            store_in_database(scan_profile, repo_context)
            
            # Cleanup
            delete_clone(clone_dir)
    
    # After all scans: compute ecosystem statistics
    compute_ecosystem_stats()


def build_repo_context(repo, clone_dir) -> RepoContext:
    ctx = RepoContext()
    ctx.repo_hash = sha256(f"{repo.owner}/{repo.name}")
    ctx.stars = repo.stargazers_count
    ctx.forks = repo.forks_count
    ctx.created_at = repo.created_at
    ctx.last_commit_at = repo.pushed_at
    ctx.contributor_count = repo.contributors_count
    ctx.is_archived = repo.archived
    ctx.primary_language = repo.language
    ctx.has_tests = _has_tests(clone_dir)
    ctx.has_ci = _has_ci(clone_dir)
    ctx.has_dockerfile = _has_dockerfile(clone_dir)
    
    # Domain inference from README
    readme = _read_readme(clone_dir)
    ctx.domain_hint, ctx.domain_confidence, ctx.domain_signals = infer_domain(
        readme, repo.name, repo.description or ""
    )
    
    # Dependency versions from requirements files
    ctx.dependency_versions = _parse_requirements(clone_dir)
    
    return ctx
```

---

## DATABASE SCHEMA

Store in Supabase (Postgres). Two tables.

```sql
CREATE TABLE scan_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id TEXT NOT NULL,
    topology_signature TEXT NOT NULL,
    scan_timestamp TIMESTAMPTZ NOT NULL,
    schema_version TEXT NOT NULL,
    
    -- Store the full ScanProfile as JSONB for flexibility
    -- Individual columns for the most-queried fields (for indexing)
    profile JSONB NOT NULL,
    
    -- Indexed query columns
    archetype TEXT,
    risk_score INTEGER,
    maturity_score INTEGER,
    agent_count INTEGER,
    crew_count INTEGER,
    max_blast_radius INTEGER,
    has_pii_flow BOOLEAN,
    matches_echoleak BOOLEAN,
    matches_any_breach BOOLEAN,
    eu_ai_act_risk_level TEXT,
    compliance_gap_count INTEGER,
    
    -- Frameworks as array for containment queries
    frameworks TEXT[],
    tool_names TEXT[],
    external_services TEXT[],
    finding_ids TEXT[],
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_topology ON scan_profiles(topology_signature);
CREATE INDEX idx_archetype ON scan_profiles(archetype);
CREATE INDEX idx_risk ON scan_profiles(risk_score);
CREATE INDEX idx_frameworks ON scan_profiles USING GIN(frameworks);
CREATE INDEX idx_tools ON scan_profiles USING GIN(tool_names);
CREATE INDEX idx_findings ON scan_profiles USING GIN(finding_ids);

CREATE TABLE repo_contexts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id TEXT NOT NULL REFERENCES scan_profiles(scan_id),
    repo_hash TEXT NOT NULL,
    
    context JSONB NOT NULL,
    
    -- Indexed query columns
    domain_hint TEXT,
    stars INTEGER,
    primary_language TEXT,
    is_active BOOLEAN,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_domain ON repo_contexts(domain_hint);
CREATE INDEX idx_repo ON repo_contexts(repo_hash);
```

---

## ENTERPRISE QUERIES THIS ENABLES

Once you have 50,000 rows in scan_profiles:

```sql
-- "What % of projects using GmailToolkit match EchoLeak?"
SELECT 
    COUNT(*) FILTER (WHERE matches_echoleak) * 100.0 / COUNT(*) AS echoleak_pct
FROM scan_profiles 
WHERE 'GmailToolkit' = ANY(tool_names);

-- "What's the median blast radius for fintech agent projects?"
SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY max_blast_radius)
FROM scan_profiles sp
JOIN repo_contexts rc ON sp.scan_id = rc.scan_id
WHERE rc.domain_hint = 'finance';

-- "What's the risk score distribution by maturity level?"
SELECT 
    profile->>'maturity_level' as maturity,
    AVG(risk_score) as avg_risk,
    percentile_cont(0.5) WITHIN GROUP (ORDER BY risk_score) as median_risk
FROM scan_profiles
GROUP BY profile->>'maturity_level';

-- "Which anti-pattern is most correlated with CRITICAL findings?"
SELECT 
    key as anti_pattern,
    COUNT(*) FILTER (WHERE (profile->'findings_by_severity'->>'critical')::int > 0) * 100.0 / COUNT(*) AS critical_pct
FROM scan_profiles,
    jsonb_each_text(profile) 
WHERE key LIKE 'has_%' AND value = 'true'
GROUP BY key
ORDER BY critical_pct DESC;

-- "If we add HITL, what's the average risk reduction for projects like ours?"
SELECT AVG(
    (elem->>'score_reduction')::int
) as avg_reduction
FROM scan_profiles,
    jsonb_array_elements(profile->'what_if_controls') as elem
WHERE elem->>'control' = 'hitl_on_outbound'
AND archetype = 'multi_agent_orchestrator'
AND 'CrewAI' = ANY(frameworks);

-- "Percentile rank for a customer's blast radius"
SELECT 
    percent_rank() WITHIN GROUP (ORDER BY max_blast_radius) * 100 as percentile
FROM scan_profiles
WHERE archetype = 'multi_agent_orchestrator';

-- Customer fleet query: "How do my 40 projects compare?"
-- (Customer's topology_signatures are known from their scans)
WITH customer AS (
    SELECT * FROM scan_profiles 
    WHERE topology_signature = ANY(ARRAY['sig1', 'sig2', ...])
),
ecosystem AS (
    SELECT * FROM scan_profiles
    WHERE archetype IN (SELECT DISTINCT archetype FROM customer)
)
SELECT 
    c.topology_signature,
    c.risk_score,
    (SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY risk_score) FROM ecosystem) as ecosystem_median,
    c.risk_score > (SELECT percentile_cont(0.75) WITHIN GROUP (ORDER BY risk_score) FROM ecosystem) as above_75th
FROM customer c;
```

---

## IMPLEMENTATION CHANGES TO THE SCANNER

### Files to modify:

1. **`models.py`** — Add ScanProfile dataclass (replace current telemetry profile model)
2. **`telemetry/profile.py`** — Replace `build_telemetry_profile()` with `build_scan_profile()` using the full population logic above
3. **`scanner.py`** — Wire `build_scan_profile()` into the scan pipeline, pass all required data
4. **`knowledge/incidents.py`** — Add path pattern flags to incident matching (inbox_to_outbound, scrape_to_action)
5. **`cli.py`** — Add `--profile-output` flag to write ScanProfile as standalone JSON (for batch pipeline)

### Files to create:

6. **`telemetry/maturity.py`** — `compute_maturity_score()` 
7. **`telemetry/regulatory.py`** — `compute_regulatory_exposure()`
8. **`telemetry/what_if.py`** — `compute_what_if_controls()`
9. **`telemetry/tools.py`** — `categorize_tools()`, tool category lookup
10. **`batch/scan_github.py`** — GitHub batch scan pipeline (separate from scanner, uses scanner as library)
11. **`batch/repo_context.py`** — `build_repo_context()`, domain inference

### What does NOT change:

- Capability detection
- Graph construction
- Finding generation
- Terminal output
- All existing rules
- Badge generation
- Flow maps

The telemetry redesign is purely additive — it consumes data the scanner already produces and enriches it into the ScanProfile format. No existing scanner behavior changes.

---

## BUILD ORDER FOR CLAUDE CODE

```
Message 1: "Read this spec. Update stratum/models.py: add the ScanProfile dataclass exactly
            as specified. This replaces the current telemetry profile model. Keep all other
            models unchanged."

Message 2: "Create stratum/telemetry/maturity.py, stratum/telemetry/regulatory.py,
            stratum/telemetry/what_if.py, stratum/telemetry/tools.py.
            Implement compute_maturity_score, compute_regulatory_exposure,
            compute_what_if_controls, and categorize_tools exactly as specified."

Message 3: "Rewrite stratum/telemetry/profile.py. Replace build_telemetry_profile with
            build_scan_profile using the full population logic from the spec. Wire in
            maturity, regulatory, what-if, and tool categorization. Ensure every field
            in ScanProfile is populated."

Message 4: "Update stratum/scanner.py to call build_scan_profile with all required arguments.
            Update stratum/cli.py to add --profile-output flag that writes the ScanProfile
            as a standalone JSON file."

Message 5: "Create stratum/batch/scan_github.py and stratum/batch/repo_context.py.
            Implement the batch scan pipeline with domain inference.
            Add a __main__.py entry point."

Message 6: "Run stratum scan on crewAI-examples. Verify the ScanProfile has all fields
            populated. Check: tool_names is a real list of tool names (not empty),
            what_if_controls has entries, maturity_score and maturity_level are computed,
            regulatory fields are populated, anti-pattern booleans are correct,
            blast_radii has per-crew entries with tool names."
```

---

## EXPECTED PROFILE FOR crewAI-examples

After implementation, the ScanProfile for crewAI-examples should look approximately like:

```json
{
  "scan_id": "...",
  "topology_signature": "f9e0f129986fd183",
  "schema_version": "2.0",
  "scan_timestamp": "2026-02-13T...",
  
  "archetype": "multi_agent_orchestrator",
  "frameworks": ["CrewAI", "LangChain"],
  "agent_count": 53,
  "crew_count": 29,
  "is_monorepo": true,
  "crew_sizes": [4, 4, 3, 3, 3, 3, 3, 3, 2, 2, ...],
  "max_chain_depth": 4,
  "has_hierarchical_crew": false,
  
  "tool_names": ["CSVSearchTool", "CalculatorTool", "FileReadTool", "GmailGetThread", "GmailToolkit", "SEC10KTool", "SEC10QTool", "ScrapeWebsiteTool", "SerperDevTool", "TavilySearchResults", "WebsiteSearchTool", "slack_sdk"],
  "tool_count": 16,
  "tool_categories": {"search": 4, "email": 2, "scraping": 2, "file": 2, "data": 3, "financial": 3, "messaging": 1, "validation": 2},
  "outbound_to_data_ratio": 1.64,
  "tools_shared_by_3_plus": 5,
  
  "external_services": ["Gmail outbound", "HTTP endpoint", "Serper API", "Slack", "Tavily API"],
  "has_email_integration": true,
  "has_messaging_integration": true,
  "has_web_scraping": true,
  "has_financial_tools": true,
  
  "risk_score": 75,
  "finding_ids": ["STRATUM-001", "STRATUM-002", "STRATUM-008", "STRATUM-009", "STRATUM-010", "STRATUM-CR01", "STRATUM-CR02", "STRATUM-CR05", "STRATUM-CR06", "STRATUM-BR01"],
  "findings_by_severity": {"critical": 2, "high": 4, "medium": 4},
  "findings_by_category": {"security": 2, "compounding": 4, "business": 2, "operational": 3},
  
  "has_unguarded_data_external": true,
  "has_blast_radius_3_plus": true,
  "has_control_bypass": true,
  "matches_echoleak": true,
  "matches_any_breach": true,
  
  "blast_radii": [
    {"tool": "ScrapeWebsiteTool", "tool_category": "scraping", "agent_count": 4, "external_count": 2, "crew_hash": "a1b2c3d4"},
    {"tool": "SerperDevTool", "tool_category": "search", "agent_count": 3, "external_count": 1, "crew_hash": "e5f6a7b8"}
  ],
  "max_blast_radius": 4,
  "total_blast_surface": 18,
  
  "maturity_score": 12,
  "maturity_level": "none",
  "has_hitl": false,
  "has_structured_output": true,
  "has_observability": false,
  "error_handling_ratio": 0.07,
  "guardrail_linked_count": 4,
  
  "has_pii_flow": true,
  "has_inbox_to_outbound": true,
  "has_scrape_to_action": true,
  "uncontrolled_path_count": 6,
  
  "eu_ai_act_risk_level": "limited",
  "eu_ai_act_gap_count": 4,
  "gdpr_relevant": true,
  "compliance_gap_count": 6,
  
  "what_if_controls": [
    {"control": "hitl_on_outbound", "findings_suppressed": ["STRATUM-001", "STRATUM-BR01", "STRATUM-002"], "score_reduction": 55, "effort": "low"},
    {"control": "shared_tool_validation", "findings_suppressed": ["STRATUM-CR05", "STRATUM-CR01"], "score_reduction": 40, "effort": "med"},
    {"control": "structured_output_validation", "findings_suppressed": ["STRATUM-CR02", "STRATUM-BR04"], "score_reduction": 16, "effort": "low"},
    {"control": "observability", "findings_suppressed": ["TELEMETRY-003", "STRATUM-BR03"], "score_reduction": 11, "effort": "low"}
  ],
  "top_recommendation": "hitl_on_outbound",
  "top_recommendation_impact": 55
}
```

That profile, multiplied by 50,000 repos, is the dataset. The dataset is the enterprise product. The enterprise product is the moat.
