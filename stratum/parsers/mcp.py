"""MCP JSON config parser.

Finds and parses MCP server configurations from JSON files.
"""
from __future__ import annotations

import json
import logging
import os
import re

from stratum.models import MCPServer
from stratum.knowledge.db import KNOWN_SAFE_PUBLISHERS

logger = logging.getLogger(__name__)

MCP_CONFIG_FILES = [
    "claude_desktop_config.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    "mcp.json",
]

AUTH_ENV_PATTERNS = ["TOKEN", "KEY", "SECRET", "AUTH", "PASSWORD", "OAUTH", "BEARER"]


def parse_mcp_configs(directory: str) -> list[MCPServer]:
    """Find and parse all MCP config files in the project."""
    servers: list[MCPServer] = []
    seen_files: set[str] = set()

    # Check known config file locations
    for config_path in MCP_CONFIG_FILES:
        full_path = os.path.join(directory, config_path)
        if os.path.isfile(full_path):
            norm = os.path.normpath(full_path)
            if norm not in seen_files:
                seen_files.add(norm)
                servers.extend(_parse_mcp_file(full_path, config_path))

    # Scan top-level JSON files for mcpServers key
    try:
        for entry in os.listdir(directory):
            if not entry.endswith(".json"):
                continue
            full_path = os.path.join(directory, entry)
            norm = os.path.normpath(full_path)
            if norm in seen_files or not os.path.isfile(full_path):
                continue
            seen_files.add(norm)
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and "mcpServers" in data:
                    servers.extend(_parse_mcp_file(full_path, entry))
            except (json.JSONDecodeError, OSError):
                pass
    except OSError:
        pass

    return servers


def _parse_mcp_file(file_path: str, relative_path: str) -> list[MCPServer]:
    """Parse a single MCP config file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.debug("Failed to parse MCP config %s: %s", file_path, e)
        return []

    if not isinstance(data, dict) or "mcpServers" not in data:
        return []

    mcp_servers = data["mcpServers"]
    if not isinstance(mcp_servers, dict):
        return []

    servers: list[MCPServer] = []
    for name, config in mcp_servers.items():
        if not isinstance(config, dict):
            continue
        server = _parse_server_entry(name, config, relative_path)
        servers.append(server)

    return servers


def _parse_server_entry(name: str, config: dict, source_file: str) -> MCPServer:
    """Parse a single MCP server entry."""
    command = config.get("command", "")
    args = config.get("args", [])
    if not isinstance(args, list):
        args = []
    url = config.get("url", "")

    # Env vars - names only
    env = config.get("env", {})
    env_vars = list(env.keys()) if isinstance(env, dict) else []

    # Transport
    transport = "unknown"
    if command:
        transport = "stdio"
    elif url:
        if "/sse" in url:
            transport = "sse"
        else:
            transport = "http"

    # Remote detection
    is_remote = bool(url)
    if not is_remote:
        for arg in args:
            if isinstance(arg, str) and "https://" in arg:
                is_remote = True
                break

    # Auth detection
    has_auth = False
    for var_name in env_vars:
        upper = var_name.upper()
        if any(pat in upper for pat in AUTH_ENV_PATTERNS):
            has_auth = True
            break

    # NPM package extraction
    npm_package = ""
    package_version = ""
    if command == "npx" and args:
        pkg_arg = args[0] if isinstance(args[0], str) else ""
        npm_package, package_version = _extract_npm_info(pkg_arg)
    elif isinstance(command, str) and "npx" in command:
        parts = command.split()
        if len(parts) > 1:
            npm_package, package_version = _extract_npm_info(parts[1])

    # Known safe check
    is_known_safe = any(
        npm_package.startswith(prefix)
        for prefix in KNOWN_SAFE_PUBLISHERS
    ) if npm_package else False

    return MCPServer(
        name=name,
        source_file=source_file,
        command=command,
        url=url,
        args=[str(a) for a in args],
        env_vars_passed=env_vars,
        transport=transport,
        is_remote=is_remote,
        has_auth=has_auth,
        npm_package=npm_package,
        package_version=package_version,
        is_known_safe=is_known_safe,
    )


def _extract_npm_info(pkg_str: str) -> tuple[str, str]:
    """Extract npm package name and version from a string like '@scope/name@version'.

    Returns (package_name, version). Version is empty if unpinned.
    """
    if not pkg_str:
        return "", ""

    # Handle scoped packages: @scope/name@version
    if pkg_str.startswith("@"):
        # @scope/name@version
        match = re.match(r"^(@[^/]+/[^@]+)@(.+)$", pkg_str)
        if match:
            return match.group(1), match.group(2)
        # @scope/name (no version)
        match = re.match(r"^(@[^/]+/[^@]+)$", pkg_str)
        if match:
            return match.group(1), ""
        return pkg_str, ""

    # Unscoped: name@version
    if "@" in pkg_str:
        parts = pkg_str.rsplit("@", 1)
        return parts[0], parts[1]

    return pkg_str, ""
