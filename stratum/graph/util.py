"""Shared utilities for graph construction."""
from __future__ import annotations


def tool_class_name(cap) -> str:
    """Extract the clean tool class name from a Capability.

    cap.function_name is '[SerperDevTool]' for framework tools.
    Returns 'SerperDevTool'.

    Falls back to the last segment of cap.library if function_name
    is a regular function name (no brackets).
    """
    name = cap.function_name.strip("[]")
    if name and name[0].isupper():
        # It's a class name like SerperDevTool, GmailToolkit
        return name
    # Fallback: last segment of library
    # "langchain_community.tools.gmail.get_thread" -> "get_thread"
    return cap.library.rsplit(".", 1)[-1] if "." in cap.library else cap.library
