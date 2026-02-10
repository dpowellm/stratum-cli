# Stratum

**Security audit for AI agents.** Finds what will break before it breaks — credential exposure, learning drift, missing guardrails, and 25+ risk patterns mapped to the [OWASP Top 10 for Agentic AI](https://genai.owasp.org).

```bash
pip install stratum-cli
stratum scan .
```

<!-- Screenshot: Terminal output showing risk score, color-coded findings, quick wins -->

---

## What it finds

Stratum reads your agent code — Python files, MCP configs, `.env` files — and detects risks across three categories:

**Security** — Data exfiltration paths, MCP credential exposure, code execution via agent tools, known CVEs

**Reliability** — Missing timeouts, no error handling, volatile state

**Governance** — Self-learning loops with no rollback, traces sent to model providers, shared agent credentials

Every finding is mapped to [OWASP ASI01-ASI10](https://genai.owasp.org) with copy-paste remediation.

## Quick start

```bash
# Audit your project
stratum scan .

# Audit and fail CI on new critical findings
stratum scan . --ci

# JSON output for automation
stratum scan . --json
```

## What makes it different

- **Not an MCP scanner.** Stratum audits the full agent: tools, memory, credentials, guardrails, telemetry, MCP configs. mcp-scan checks MCP servers. Stratum checks the agent that uses them.
- **Reliability first.** Leads with what will crash your agent in production (timeouts, error handling) before what could exploit it (prompt injection, exfiltration). Fixes the urgent thing first.
- **Research-backed.** Every finding cites the research behind it — MCPTox, Pynt, OWASP. Not opinions. Evidence.
- **No account, no API key.** Fully local analysis. Your code never leaves your machine.

## Telemetry

Stratum sends anonymized scan statistics (capability counts, risk scores,
finding severities — never source code, file paths, or secrets) to improve
agent security research. Full details: [docs/telemetry.md](docs/telemetry.md).

Disable permanently: `stratum config set telemetry off`
Disable for one scan: `stratum scan . --no-telemetry`

## Add to CI

```yaml
# .github/workflows/stratum.yml
name: Agent Security Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install stratum-cli
      - run: stratum scan . --ci
```

## Badge

After running a scan, add the badge to your README:

```markdown
![Stratum Risk Score](https://img.shields.io/badge/stratum_risk-42%2F100-yellow)
```

## How it works

Stratum parses your Python files via AST, reads MCP JSON configs, and checks `.env` files. No LLM. No network. No framework-specific logic. If your code imports `subprocess` and calls `subprocess.run()`, Stratum finds it — regardless of whether you're using LangChain, CrewAI, or raw Python.

Risk paths are identified by combining capabilities (what your agent can do) with missing controls (what's not protecting it). A data access tool + an outbound tool + no output filter = data exfiltration path. That's a CRITICAL finding.

The risk score (0-100) is computed from finding severities with bonuses for structural gaps (no guardrails, no timeouts, shared credentials). Track it over time with `stratum scan .` — it saves history to `.stratum/`.

## Documentation

- [All findings explained](docs/findings.md)
- [OWASP ASI mapping](docs/owasp.md)
- [CI integration guide](docs/ci.md)
- [How scoring works](docs/scoring.md)

## License

[BSL 1.1](LICENSE) — free to use, source-available. See [why](docs/license.md).
