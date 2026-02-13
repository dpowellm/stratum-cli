"""Tool categorization for ScanProfile intelligence."""
from __future__ import annotations


TOOL_CATEGORIES: dict[str, list[str]] = {
    # Search & Research
    "search": [
        "SerperDevTool", "TavilySearchResults", "WebsiteSearchTool",
        "web_search_tool", "seper_dev_tool", "DuckDuckGoSearchRun",
    ],
    # Email
    "email": [
        "GmailToolkit", "GmailGetThread", "GmailSendMessage",
        "GmailCreateDraft", "OutlookToolkit",
    ],
    # Messaging
    "messaging": [
        "slack_sdk", "SlackToolkit", "TeamsToolkit", "DiscordToolkit",
    ],
    # Web Scraping
    "scraping": [
        "ScrapeWebsiteTool", "requests", "BeautifulSoup", "SeleniumTool",
    ],
    # File System
    "file": [
        "FileReadTool", "FileManagementToolkit", "file_read_tool",
        "FileWriteTool", "DirectoryReadTool",
    ],
    # Data / Database
    "data": [
        "CSVSearchTool", "TXTSearchTool", "RagTool", "PDFSearchTool",
        "JSONSearchTool", "ChromaDB", "PGSearchTool",
    ],
    # Financial
    "financial": [
        "SEC10KTool", "SEC10QTool", "CalculatorTool", "YFinanceTool",
        "AlphaVantageTool",
    ],
    # Code Execution
    "code_exec": [
        "CodeInterpreterTool", "PythonREPLTool", "BashTool", "exec",
    ],
    # Social / Publishing
    "social": [
        "LinkedInTool", "TwitterTool", "InstagramTool",
    ],
    # Project Management
    "project": [
        "TrelloTool", "JiraTool", "AsanaTool", "NotionTool",
    ],
    # Validation / Internal
    "validation": [
        "CharacterCounterTool", "markdown_validation_tool", "SchemaTool",
    ],
}


def categorize_tools(tool_names: list[str]) -> dict[str, int]:
    """Categorize a list of tool names into counts per category.

    Returns e.g. {"search": 3, "email": 2, "other": 1}.
    """
    categories: dict[str, int] = {}
    for tool in tool_names:
        cat = categorize_single_tool(tool)
        categories[cat] = categories.get(cat, 0) + 1
    return categories


def categorize_single_tool(tool_name: str) -> str:
    """Return the category for a single tool name, or "other"."""
    for category, known_tools in TOOL_CATEGORIES.items():
        if any(known in tool_name for known in known_tools):
            return category
    return "other"
