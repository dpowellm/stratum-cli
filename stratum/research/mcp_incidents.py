"""Known MCP security incidents.

Manually curated from public advisories. Updated periodically.
Each entry maps an npm package name or MCP server identifier
to a known incident with severity, description, and source.
"""
from __future__ import annotations

import dataclasses


@dataclasses.dataclass
class MCPIncident:
    package: str            # npm package name or identifier
    severity: str           # CRITICAL, HIGH, MEDIUM
    cve: str               # CVE ID if available
    description: str        # One-line description
    affected_versions: str  # Version range
    fixed_version: str      # Version that fixes it, or ""
    source_url: str         # Verification URL


KNOWN_INCIDENTS: list[MCPIncident] = [
    MCPIncident(
        package="postmark-mcp",
        severity="CRITICAL",
        cve="",
        description="Malicious BCC exfiltrated all emails to attacker. First confirmed malicious MCP server.",
        affected_versions=">=1.0.16",
        fixed_version="removed from npm",
        source_url="https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/",
    ),
    MCPIncident(
        package="mcp-remote",
        severity="CRITICAL",
        cve="CVE-2025-6514",
        description="RCE via OS commands in OAuth discovery fields. CVSS 9.6. 500K+ downloads.",
        affected_versions="<0.1.16",
        fixed_version="0.1.16",
        source_url="https://composio.dev/blog/mcp-vulnerabilities-every-developer-should-know",
    ),
    MCPIncident(
        package="@anthropic/mcp-inspector",
        severity="CRITICAL",
        cve="CVE-2025-49596",
        description="RCE in Anthropic's MCP Inspector via browser-based attack.",
        affected_versions="",
        fixed_version="patched",
        source_url="",
    ),
]


def _version_gte(version_str: str, fixed_str: str) -> bool:
    """Semver comparison: True if version_str >= fixed_str."""
    try:
        def parse(v: str) -> tuple[int, ...]:
            return tuple(int(x) for x in v.strip().split("."))
        return parse(version_str) >= parse(fixed_str)
    except (ValueError, AttributeError):
        return False


def check_mcp_config(server_name: str, package_args: list[str]) -> list[MCPIncident]:
    """Check MCP server config against known incidents.

    Args:
        server_name: The key in mcpServers config
        package_args: The args array (e.g. ["mcp-remote", ...] or ["postmark-mcp"])

    Returns:
        List of matching incidents (usually 0 or 1)
    """
    matches = []
    for arg in package_args:
        # Strip version pinning for matching: "mcp-remote@0.1.5" -> "mcp-remote"
        base_package = arg.split("@")[0] if "@" in arg else arg
        for incident in KNOWN_INCIDENTS:
            if incident.package == base_package:
                # If version is pinned and a fixed version exists, check if it's fixed
                if "@" in arg and incident.fixed_version and incident.fixed_version != "removed from npm" and incident.fixed_version != "patched":
                    pinned_version = arg.split("@")[1]
                    if _version_gte(pinned_version, incident.fixed_version):
                        continue  # Fixed version, skip
                matches.append(incident)
    return matches
