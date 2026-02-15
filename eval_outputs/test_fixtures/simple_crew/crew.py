"""Simple 3-agent crewAI project for evaluation.

This fixture demonstrates:
- 3 agents with delegation
- Shared data store (shared_memory)
- Irreversible capability (delete_records) without approval gate
- No human_input on any task
- Silent error handling (try/except returning defaults)
"""
from crewai import Agent, Crew, Task
from crewai_tools import SerperDevTool, FileReadTool

# Tools
search_tool = SerperDevTool()
file_tool = FileReadTool()


def delete_records(record_ids: list[str]) -> str:
    """Permanently delete records from the database. IRREVERSIBLE."""
    import psycopg2
    conn = psycopg2.connect(dsn="postgresql://admin:secret@db:5432/prod")
    cur = conn.cursor()
    for rid in record_ids:
        cur.execute("DELETE FROM records WHERE id = %s", (rid,))
    conn.commit()
    return f"Deleted {len(record_ids)} records"


def send_email(to: str, subject: str, body: str) -> str:
    """Send email via SMTP."""
    import smtplib
    server = smtplib.SMTP("smtp.company.com", 587)
    server.login("agent@company.com", "password123")
    server.sendmail("agent@company.com", to, f"Subject: {subject}\n\n{body}")
    return "sent"


# Shared data store
shared_memory = {}


def write_to_shared(key: str, value: str) -> str:
    """Write to shared memory store."""
    shared_memory[key] = value
    return "ok"


def read_from_shared(key: str) -> str:
    """Read from shared memory store."""
    try:
        return shared_memory[key]
    except KeyError:
        return "default_value"  # Silent error: returns default instead of raising


# Agents
manager = Agent(
    role="Project Manager",
    goal="Coordinate research and analysis tasks",
    backstory="Senior project manager with delegation authority",
    tools=[search_tool, write_to_shared, read_from_shared],
    allow_delegation=True,
    verbose=True,
)

researcher = Agent(
    role="Research Analyst",
    goal="Research topics and compile findings",
    backstory="Expert researcher with access to search and files",
    tools=[search_tool, file_tool, write_to_shared, read_from_shared],
    allow_delegation=True,
    verbose=True,
)

executor = Agent(
    role="Action Executor",
    goal="Execute actions based on research findings",
    backstory="Executor with database and email access",
    tools=[delete_records, send_email, read_from_shared],
    allow_delegation=False,
    verbose=True,
)

# Tasks (no human_input on any task)
research_task = Task(
    description="Research the topic and store findings in shared memory",
    expected_output="Research summary stored in shared memory",
    agent=researcher,
)

analysis_task = Task(
    description="Analyze research findings and determine actions",
    expected_output="Action plan based on research",
    agent=manager,
)

execution_task = Task(
    description="Execute the action plan: delete old records and notify stakeholders",
    expected_output="Confirmation of executed actions",
    agent=executor,
)

# Crew
crew = Crew(
    agents=[manager, researcher, executor],
    tasks=[research_task, analysis_task, execution_task],
    verbose=True,
)

if __name__ == "__main__":
    result = crew.kickoff()
    print(result)
