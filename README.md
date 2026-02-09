# Stratum CLI

Agent Risk Profiler. Scans AI agent project directories and outputs a risk profile.

`pip install stratum-cli && stratum scan .` — top risk paths in 3 seconds.

## Install

```bash
pip install -e .
```

## Usage

```bash
# Scan current directory
stratum scan .

# Scan a specific directory
stratum scan ./my-agent-project/

# Verbose output (expand all signals)
stratum scan . --verbose

# JSON output
stratum scan . --json

# CI mode (exit codes: 1=CRITICAL, 2=HIGH)
stratum scan . --ci
```

## What It Detects

**6 capability classes:**
- MCP server configs (CVEs, unpinned packages, credential exposure)
- Outbound tools (HTTP, email, messaging, payment SDKs)
- Data access (SQL, NoSQL, Redis)
- Code execution (subprocess, os.system, exec/eval)
- Destructive writes (DELETE, DROP, TRUNCATE with DB provenance)
- Financial operations (Stripe, PayPal, Square, Braintree)

**10 risk path rules (top 5 displayed):**
- STRATUM-001: Data exfiltration path
- STRATUM-002: Destructive action, no human gate
- STRATUM-003: Code execution via agent tool
- STRATUM-004: Known CVE in MCP config
- STRATUM-005: MCP credential exposure
- STRATUM-006: MCP supply chain risk
- STRATUM-007: Unvalidated financial operation
- STRATUM-008: No error handling on external dependencies
- STRATUM-009: No timeout on HTTP calls
- STRATUM-010: Volatile agent state

## Example Output

```
┌─────────────────────────────────────────────────────────────────┐
│   STRATUM · Agent Risk Profiler                        v0.1.0  │
└─────────────────────────────────────────────────────────────────┘
  13 capabilities (5 outbound, 5 data access, 1 code exec,
  1 destructive, 1 financial)
  5 MCP servers · 0 guardrails

  ▸ 11 security · 1 business · 3 operational

  RISK SCORE  100/100  ████████████████████  CRITICAL

──────────────────── TOP RISK PATHS ────────────────────────

 ● CRITICAL · confirmed · security        STRATUM-001
 Data Exfiltration Path

 get_customer_data (psycopg2) -> no output filter ->
 send_email (smtplib)

 ● CRITICAL · confirmed · security        STRATUM-002
 Destructive Action, No Human Gate

 ● CRITICAL · confirmed · security        STRATUM-004
 Known Vulnerable MCP: mcp-remote

 ● HIGH · confirmed · security            STRATUM-003
 Code Execution via Agent Tool

 ● HIGH · confirmed · security            STRATUM-005
 Production Credentials to Third-Party MCP

──────────────────── SIGNALS (10 more) ─────────────────────

 ● HIGH  STRATUM-006  Unpinned MCP            security
 ● HIGH  STRATUM-007  Unvalidated Financial   business
 ● MED   STRATUM-008  No error handling       operational
 ● MED   STRATUM-009  No timeout on HTTP      operational
 ● MED   STRATUM-010  In-memory-only state    operational
 ● MED   ENV-001      .env not in .gitignore  security
```

## How It Works

Framework-agnostic AST analysis. If a Python function has `subprocess.run()`, Stratum finds it — regardless of whether it's LangGraph, CrewAI, or raw Python.

**Confidence levels prevent false positives:**
- **CONFIRMED**: Import resolved to call site (e.g., `import requests` + `requests.post()`)
- **PROBABLE**: Strong inference (e.g., SQL keyword in function with DB import)
- **HEURISTIC**: Unresolved method — capped at MEDIUM severity, never in top paths

**Hard rule:** Zero CRITICAL/HIGH findings from HEURISTIC evidence.
