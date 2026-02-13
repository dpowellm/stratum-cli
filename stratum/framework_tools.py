"""Known framework tool -> capability mapping.

When the scanner sees an import or instantiation of a known tool,
it emits capabilities without parsing the tool's internal source code.
The tool's behavior is known -- we just need to recognize the import.

This is a static registry. It covers the most common tools from:
- crewai_tools
- langchain_community.tools
- langchain_community.agent_toolkits
- langchain_community.utilities
- autogen (built-in capabilities)
- llama_index.tools

To add a new tool: add an entry to KNOWN_TOOLS with the class name
as key and a ToolProfile as value.

Confidence for all registry-derived capabilities: CONFIRMED.
The mapping is curated -- if it's in this list, we're sure what it does.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ToolProfile:
    """What a known framework tool does."""
    kinds: list[str] = field(default_factory=list)
    detail: str = ""
    source_modules: list[str] = field(default_factory=list)


# -------------------------------------------------------------------
# REGISTRY
# -------------------------------------------------------------------
KNOWN_TOOLS: dict[str, ToolProfile] = {

    # ============================================================
    # WEB SEARCH / SCRAPING (outbound)
    # ============================================================
    "SerperDevTool": ToolProfile(
        kinds=["outbound"],
        detail="Web search via Serper API",
        source_modules=["crewai_tools"],
    ),
    "ScrapeWebsiteTool": ToolProfile(
        kinds=["outbound"],
        detail="Web scraping / URL fetching",
        source_modules=["crewai_tools"],
    ),
    "WebsiteSearchTool": ToolProfile(
        kinds=["outbound"],
        detail="Website content search",
        source_modules=["crewai_tools"],
    ),
    "BrowserbaseLoadTool": ToolProfile(
        kinds=["outbound"],
        detail="Browser-based web loading",
        source_modules=["crewai_tools"],
    ),
    "FirecrawlSearchTool": ToolProfile(
        kinds=["outbound"],
        detail="Web search via Firecrawl",
        source_modules=["crewai_tools"],
    ),
    "FirecrawlScrapeWebsiteTool": ToolProfile(
        kinds=["outbound"],
        detail="Web scraping via Firecrawl",
        source_modules=["crewai_tools"],
    ),
    "FirecrawlCrawlWebsiteTool": ToolProfile(
        kinds=["outbound"],
        detail="Website crawling via Firecrawl",
        source_modules=["crewai_tools"],
    ),
    "EXASearchTool": ToolProfile(
        kinds=["outbound"],
        detail="Web search via EXA",
        source_modules=["crewai_tools"],
    ),
    "SerpAPIWrapper": ToolProfile(
        kinds=["outbound"],
        detail="Web search via SerpAPI",
        source_modules=["langchain_community.utilities", "langchain.utilities"],
    ),
    "GoogleSearchAPIWrapper": ToolProfile(
        kinds=["outbound"],
        detail="Web search via Google API",
        source_modules=["langchain_community.utilities"],
    ),
    "GoogleSerperAPIWrapper": ToolProfile(
        kinds=["outbound"],
        detail="Web search via Google Serper",
        source_modules=["langchain_community.utilities"],
    ),
    "DuckDuckGoSearchRun": ToolProfile(
        kinds=["outbound"],
        detail="Web search via DuckDuckGo",
        source_modules=["langchain_community.tools"],
    ),
    "TavilySearchResults": ToolProfile(
        kinds=["outbound"],
        detail="Web search via Tavily",
        source_modules=["langchain_community.tools.tavily_search"],
    ),
    "BraveSearch": ToolProfile(
        kinds=["outbound"],
        detail="Web search via Brave",
        source_modules=["langchain_community.tools"],
    ),
    "WikipediaQueryRun": ToolProfile(
        kinds=["outbound", "data_access"],
        detail="Wikipedia search and retrieval",
        source_modules=["langchain_community.tools"],
    ),
    "ArxivQueryRun": ToolProfile(
        kinds=["outbound", "data_access"],
        detail="Arxiv paper search and retrieval",
        source_modules=["langchain_community.tools"],
    ),
    "PubmedQueryRun": ToolProfile(
        kinds=["outbound", "data_access"],
        detail="PubMed search and retrieval",
        source_modules=["langchain_community.tools"],
    ),
    "RequestsGetTool": ToolProfile(
        kinds=["outbound"],
        detail="HTTP GET requests",
        source_modules=["langchain_community.tools.requests_tool"],
    ),
    "RequestsPostTool": ToolProfile(
        kinds=["outbound"],
        detail="HTTP POST requests",
        source_modules=["langchain_community.tools.requests_tool"],
    ),

    # ============================================================
    # EMAIL (data_access + outbound)
    # ============================================================
    "GmailToolkit": ToolProfile(
        kinds=["data_access", "outbound"],
        detail="Gmail read + write access",
        source_modules=["langchain_community.agent_toolkits"],
    ),
    "GmailCreateDraft": ToolProfile(
        kinds=["outbound"],
        detail="Gmail draft creation (email send)",
        source_modules=["langchain_community.tools.gmail.create_draft", "langchain_community.tools.gmail"],
    ),
    "GmailSendMessage": ToolProfile(
        kinds=["outbound"],
        detail="Gmail send message",
        source_modules=["langchain_community.tools.gmail.send_message", "langchain_community.tools.gmail"],
    ),
    "GmailGetThread": ToolProfile(
        kinds=["data_access"],
        detail="Gmail thread reading",
        source_modules=["langchain_community.tools.gmail.get_thread", "langchain_community.tools.gmail"],
    ),
    "GmailGetMessage": ToolProfile(
        kinds=["data_access"],
        detail="Gmail message reading",
        source_modules=["langchain_community.tools.gmail.get_message", "langchain_community.tools.gmail"],
    ),
    "GmailSearch": ToolProfile(
        kinds=["data_access"],
        detail="Gmail search",
        source_modules=["langchain_community.tools.gmail.search", "langchain_community.tools.gmail"],
    ),
    "O365Toolkit": ToolProfile(
        kinds=["data_access", "outbound"],
        detail="Microsoft 365 email + calendar access",
        source_modules=["langchain_community.agent_toolkits"],
    ),

    # ============================================================
    # MESSAGING / COMMUNICATION (outbound)
    # ============================================================
    "SlackToolkit": ToolProfile(
        kinds=["data_access", "outbound"],
        detail="Slack read + write access",
        source_modules=["langchain_community.agent_toolkits"],
    ),

    # ============================================================
    # FILE SYSTEM (data_access, potentially destructive)
    # ============================================================
    "FileReadTool": ToolProfile(
        kinds=["data_access"],
        detail="Local file reading",
        source_modules=["crewai_tools"],
    ),
    "FileWriterTool": ToolProfile(
        kinds=["destructive"],
        detail="Local file writing",
        source_modules=["crewai_tools"],
    ),
    "DirectoryReadTool": ToolProfile(
        kinds=["data_access"],
        detail="Directory listing",
        source_modules=["crewai_tools"],
    ),
    "DirectorySearchTool": ToolProfile(
        kinds=["data_access"],
        detail="Directory content search",
        source_modules=["crewai_tools"],
    ),
    "TXTSearchTool": ToolProfile(
        kinds=["data_access"],
        detail="Text file search",
        source_modules=["crewai_tools"],
    ),
    "CSVSearchTool": ToolProfile(
        kinds=["data_access"],
        detail="CSV file search",
        source_modules=["crewai_tools"],
    ),
    "JSONSearchTool": ToolProfile(
        kinds=["data_access"],
        detail="JSON file search",
        source_modules=["crewai_tools"],
    ),
    "PDFSearchTool": ToolProfile(
        kinds=["data_access"],
        detail="PDF content search",
        source_modules=["crewai_tools"],
    ),
    "DOCXSearchTool": ToolProfile(
        kinds=["data_access"],
        detail="DOCX content search",
        source_modules=["crewai_tools"],
    ),
    "MDXSearchTool": ToolProfile(
        kinds=["data_access"],
        detail="MDX content search",
        source_modules=["crewai_tools"],
    ),
    "ReadFileTool": ToolProfile(
        kinds=["data_access"],
        detail="Local file reading",
        source_modules=["langchain_community.tools.file_management"],
    ),
    "WriteFileTool": ToolProfile(
        kinds=["destructive"],
        detail="Local file writing",
        source_modules=["langchain_community.tools.file_management"],
    ),
    "CopyFileTool": ToolProfile(
        kinds=["data_access", "destructive"],
        detail="File copy operations",
        source_modules=["langchain_community.tools.file_management"],
    ),
    "MoveFileTool": ToolProfile(
        kinds=["destructive"],
        detail="File move operations",
        source_modules=["langchain_community.tools.file_management"],
    ),
    "DeleteFileTool": ToolProfile(
        kinds=["destructive"],
        detail="File deletion",
        source_modules=["langchain_community.tools.file_management"],
    ),
    "ListDirectoryTool": ToolProfile(
        kinds=["data_access"],
        detail="Directory listing",
        source_modules=["langchain_community.tools.file_management"],
    ),
    "FileManagementToolkit": ToolProfile(
        kinds=["data_access", "destructive"],
        detail="Full file management (read, write, move, delete)",
        source_modules=["langchain_community.agent_toolkits"],
    ),

    # ============================================================
    # DATABASE (data_access, potentially destructive)
    # ============================================================
    "SQLDatabaseToolkit": ToolProfile(
        kinds=["data_access", "destructive"],
        detail="SQL database read + write",
        source_modules=["langchain_community.agent_toolkits"],
    ),
    "QuerySQLDataBaseTool": ToolProfile(
        kinds=["data_access"],
        detail="SQL query execution",
        source_modules=["langchain_community.tools.sql_database.tool"],
    ),
    "PGSearchTool": ToolProfile(
        kinds=["data_access"],
        detail="PostgreSQL search",
        source_modules=["crewai_tools"],
    ),
    "NL2SQLTool": ToolProfile(
        kinds=["data_access", "destructive"],
        detail="Natural language to SQL (read + potential write)",
        source_modules=["crewai_tools"],
    ),

    # ============================================================
    # CODE EXECUTION (code_exec)
    # ============================================================
    "CodeInterpreterTool": ToolProfile(
        kinds=["code_exec"],
        detail="Python code execution in sandbox",
        source_modules=["crewai_tools"],
    ),
    "CodeDocsSearchTool": ToolProfile(
        kinds=["outbound"],
        detail="Code documentation search",
        source_modules=["crewai_tools"],
    ),
    "PythonREPLTool": ToolProfile(
        kinds=["code_exec"],
        detail="Python REPL execution",
        source_modules=["langchain_community.tools", "langchain_experimental.tools"],
    ),
    "ShellTool": ToolProfile(
        kinds=["code_exec"],
        detail="Shell command execution",
        source_modules=["langchain_community.tools"],
    ),
    "BashProcess": ToolProfile(
        kinds=["code_exec"],
        detail="Bash process execution",
        source_modules=["langchain_experimental.llm_bash"],
    ),

    # ============================================================
    # VECTOR / RAG (data_access)
    # ============================================================
    "RagTool": ToolProfile(
        kinds=["data_access"],
        detail="RAG retrieval from knowledge base",
        source_modules=["crewai_tools"],
    ),
    "VectorStoreQATool": ToolProfile(
        kinds=["data_access"],
        detail="Vector store Q&A retrieval",
        source_modules=["langchain.tools"],
    ),

    # ============================================================
    # GITHUB / VERSION CONTROL
    # ============================================================
    "GithubToolkit": ToolProfile(
        kinds=["data_access", "outbound"],
        detail="GitHub API access (repos, issues, PRs)",
        source_modules=["crewai_tools", "langchain_community.agent_toolkits"],
    ),
    "GithubSearchTool": ToolProfile(
        kinds=["outbound", "data_access"],
        detail="GitHub search",
        source_modules=["crewai_tools"],
    ),

    # ============================================================
    # API / INTEGRATION (outbound)
    # ============================================================
    "YoutubeVideoSearchTool": ToolProfile(
        kinds=["outbound"],
        detail="YouTube video search",
        source_modules=["crewai_tools"],
    ),
    "YoutubeChannelSearchTool": ToolProfile(
        kinds=["outbound"],
        detail="YouTube channel search",
        source_modules=["crewai_tools"],
    ),
    "SpiderTool": ToolProfile(
        kinds=["outbound"],
        detail="Web spider / crawler",
        source_modules=["crewai_tools"],
    ),
    "APITool": ToolProfile(
        kinds=["outbound"],
        detail="Generic API calling tool",
        source_modules=["crewai_tools"],
    ),
    "ZapierToolkit": ToolProfile(
        kinds=["outbound", "data_access", "destructive"],
        detail="Zapier NLA -- triggers arbitrary Zapier actions",
        source_modules=["langchain_community.agent_toolkits"],
    ),
    "ZapierNLARunAction": ToolProfile(
        kinds=["outbound", "data_access", "destructive"],
        detail="Zapier NLA -- runs arbitrary Zapier action",
        source_modules=["langchain_community.tools.zapier"],
    ),
    "JiraToolkit": ToolProfile(
        kinds=["data_access", "outbound"],
        detail="Jira issue management",
        source_modules=["langchain_community.agent_toolkits"],
    ),

    # ============================================================
    # MCP ADAPTER
    # ============================================================
    "MCPServerAdapter": ToolProfile(
        kinds=["outbound"],
        detail="MCP server adapter -- capabilities depend on connected server",
        source_modules=["crewai_tools"],
    ),

    # ============================================================
    # LLAMA INDEX TOOLS
    # ============================================================
    "QueryEngineTool": ToolProfile(
        kinds=["data_access"],
        detail="LlamaIndex query engine (RAG retrieval)",
        source_modules=["llama_index.tools", "llama_index.core.tools"],
    ),
    "FunctionTool": ToolProfile(
        kinds=[],  # capabilities come from the wrapped function
        detail="LlamaIndex function wrapper",
        source_modules=["llama_index.tools", "llama_index.core.tools"],
    ),
}


# -------------------------------------------------------------------
# FRAMEWORK DETECTION SIGNALS
# -------------------------------------------------------------------
AGENT_FRAMEWORK_IMPORTS: dict[str, str] = {
    "crewai": "CrewAI",
    "crewai_tools": "CrewAI",
    "langgraph": "LangGraph",
    "langchain": "LangChain",
    "langchain_community": "LangChain",
    "langchain_core": "LangChain",
    "langchain_experimental": "LangChain",
    "langchain_openai": "LangChain",
    "langchain_anthropic": "LangChain",
    "autogen": "AutoGen",
    "pydantic_ai": "PydanticAI",
    "llama_index": "LlamaIndex",
    "smolagents": "SmolAgents",
    "semantic_kernel": "Semantic Kernel",
    "agno": "Agno",
    "phidata": "Phidata",
}


# -------------------------------------------------------------------
# CODE EXECUTION CONFIG PATTERNS
# -------------------------------------------------------------------
CODE_EXEC_CONSTRUCTORS: dict[str, str] = {
    "UserProxyAgent": "autogen",
    "AssistantAgent": "autogen",
    "DockerCommandLineCodeExecutor": "autogen",
    "LocalCommandLineCodeExecutor": "autogen",
}
