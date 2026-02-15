"""
Multi-agent CrewAI fixture for reliability scanner evaluation.
3 agents, delegation, shared state, mixed error handling, irreversible actions.
"""
import os
from crewai import Agent, Task, Crew, Process
from crewai_tools import SerperDevTool, FileReadTool

# Three agents with different roles and error handling patterns
researcher = Agent(
    role="Senior Research Analyst",
    goal="Find comprehensive market data and competitor analysis",
    backstory="Expert at finding and synthesizing market data from multiple sources",
    tools=[SerperDevTool(), FileReadTool()],
    allow_delegation=False,
    verbose=True,
)

analyst = Agent(
    role="Financial Analyst",
    goal="Minimize risk while maximizing portfolio returns",
    backstory="Experienced financial analyst specializing in risk assessment",
    tools=[],
    allow_delegation=True,
    verbose=True,
)

executor = Agent(
    role="Trade Executor",
    goal="Execute approved trades accurately and efficiently",
    backstory="Responsible for executing financial transactions",
    tools=[],
    allow_delegation=False,
    verbose=True,
)

# Database connection (shared state)
import psycopg2
DB_CONN = os.environ.get("DATABASE_URL", "postgresql://user:password123@localhost:5432/trades")

def read_portfolio(query: str) -> str:
    """Read portfolio positions from database."""
    try:
        conn = psycopg2.connect(DB_CONN)
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM positions WHERE {query}")
        results = cur.fetchall()
        conn.close()
        return str(results)
    except Exception:
        return []

def write_trade(trade_data: dict) -> str:
    """Execute a trade and record it in the database. IRREVERSIBLE."""
    try:
        conn = psycopg2.connect(DB_CONN)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO trades (symbol, quantity, price, side) VALUES (%s, %s, %s, %s)",
            (trade_data["symbol"], trade_data["quantity"], trade_data["price"], trade_data["side"])
        )
        conn.commit()
        conn.close()
        return "Trade executed"
    except Exception:
        pass

def send_notification(recipient: str, message: str) -> str:
    """Send email notification about trade execution. IRREVERSIBLE."""
    import smtplib
    from email.mime.text import MIMEText
    msg = MIMEText(message)
    msg["Subject"] = "Trade Notification"
    msg["To"] = recipient
    with smtplib.SMTP("smtp.company.com") as server:
        server.send_message(msg)
    return "Notification sent"

# Error handling patterns differ by agent:
# researcher: uses try/except with defaults (default_on_error -> fail_silent risk)
# analyst: propagates errors (fail_loud)
# executor: catches and returns None (fail_silent)

# Tasks with explicit ordering and context flow
research_task = Task(
    description="Research market conditions for tech sector stocks",
    expected_output="Market analysis report with key metrics",
    agent=researcher,
)

analysis_task = Task(
    description="Analyze the research and recommend specific trades with risk scores",
    expected_output="Trade recommendations with risk assessment",
    agent=analyst,
    context=[research_task],  # feeds_into: researcher -> analyst
)

execution_task = Task(
    description="Execute the recommended trades and send confirmation emails",
    expected_output="Trade execution confirmation",
    agent=executor,
    context=[analysis_task],  # feeds_into: analyst -> executor
)

# Crew with sequential process -- no human checkpoint
crew = Crew(
    agents=[researcher, analyst, executor],
    tasks=[research_task, analysis_task, execution_task],
    process=Process.sequential,
    verbose=True,
)
