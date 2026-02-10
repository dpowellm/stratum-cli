"""Multi-agent system with shared memory and learning loops.

This fixture demonstrates governance gaps that Stratum should detect:
- Self-referential learning loop (read + write to same store)
- Unbounded memory accumulation (no TTL, no limits)
- Shared context across agents (same collection)
- No provenance on writes
- No versioning / rollback
- Shared API credentials
- No unique agent identifiers
- Telemetry to external provider
- Eval provider conflict
"""

import os
import json
from datetime import datetime

import openai
import chromadb
from chromadb.config import Settings

# Both agents share credentials -- no per-agent keys
client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Shared vector store -- no namespace, no TTL, no size limit
chroma_client = chromadb.Client(Settings(anonymized_telemetry=False))
memory = chroma_client.get_or_create_collection("agent_memory")

# LangSmith tracing enabled via env vars
# (LANGCHAIN_TRACING_V2=true and LANGSMITH_API_KEY are expected in .env)
os.environ.get("LANGCHAIN_TRACING_V2")
os.environ.get("LANGSMITH_API_KEY")

# OpenAI evals for evaluation -- same provider as the model
try:
    import openai.evals
except ImportError:
    pass


def research_agent(query: str) -> str:
    """Agent that researches a topic and stores findings in shared memory."""

    # Read from memory -- check if we've researched this before
    existing = memory.query(query_texts=[query], n_results=3)

    context = ""
    if existing and existing["documents"][0]:
        context = "\n".join(existing["documents"][0])

    # Call OpenAI
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": f"You are a research agent. Prior knowledge:\n{context}"},
            {"role": "user", "content": query}
        ]
    )

    result = response.choices[0].message.content

    # Write back to memory -- no provenance metadata, no TTL
    memory.add(
        documents=[result],
        ids=[f"research_{datetime.now().timestamp()}"],
    )

    return result


def writer_agent(topic: str) -> str:
    """Agent that writes content based on shared memory from research agent."""

    # Read from the SAME memory store as research_agent
    research = memory.query(query_texts=[topic], n_results=5)

    context = "\n".join(research["documents"][0]) if research["documents"][0] else ""

    # Same OpenAI client, same API key
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": f"Write a blog post. Research:\n{context}"},
            {"role": "user", "content": f"Write about: {topic}"}
        ]
    )

    result = response.choices[0].message.content

    # Writer also writes back to shared memory
    memory.add(
        documents=[result],
        ids=[f"writing_{datetime.now().timestamp()}"],
    )

    return result


def run_pipeline(query: str):
    """Run research -> writing pipeline."""
    research = research_agent(query)
    article = writer_agent(query)

    # Log results (no structured telemetry, just print)
    print(json.dumps({
        "query": query,
        "research_length": len(research),
        "article_length": len(article),
    }))

    return article
