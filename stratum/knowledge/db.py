"""Knowledge base: CVEs, attack patterns, safe publishers, capability patterns."""

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
    "mcp-tool-poisoning": {
        "name": "MCP Tool Poisoning",
        "description": "Malicious MCP server provides poisoned tool descriptions that manipulate agent behavior.",
        "mitre": "T1195.002",
    },
    "mcp-rug-pull": {
        "name": "MCP Rug Pull",
        "description": "MCP server changes behavior after initial trust is established.",
        "mitre": "T1195.002",
    },
    "mcp-credential-passthrough": {
        "name": "MCP Credential Passthrough",
        "description": "Production credentials passed directly to third-party MCP server process.",
        "mitre": "T1552.001",
    },
    "cross-tool-exfiltration": {
        "name": "Cross-Tool Exfiltration",
        "description": "Agent reads sensitive data via one tool and exfiltrates via another.",
        "mitre": "T1041",
    },
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

CODE_EXEC_FUNCTIONS: dict[str, list[str]] = {
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

HTTP_LIBRARIES = {"requests", "httpx", "aiohttp"}
