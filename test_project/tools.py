"""Agent tools. Deliberately insecure for testing."""
import os
from langchain_core.tools import tool

@tool
def get_customer_data(customer_id: str) -> str:
    """Fetch customer record from database."""
    import psycopg2
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM customers WHERE id = '{customer_id}'")
    return str(cursor.fetchone())

@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a customer."""
    import smtplib
    from email.mime.text import MIMEText
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["To"] = to
    server = smtplib.SMTP("smtp.company.com", 587)
    server.starttls()
    server.sendmail("support@company.com", to, msg.as_string())
    server.quit()
    return f"Email sent to {to}"

@tool
def delete_record(table: str, record_id: str) -> str:
    """Delete a record from the database."""
    import psycopg2
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM {table} WHERE id = '{record_id}'")
    conn.commit()
    return f"Deleted {record_id} from {table}"

@tool
def run_shell_command(command: str) -> str:
    """Run a shell command on the server."""
    import subprocess
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

@tool
def process_refund(order_id: str, amount: float) -> str:
    """Process a refund for a customer order."""
    import stripe
    stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
    refund = stripe.Refund.create(charge=order_id, amount=int(amount * 100))
    return f"Refund processed: {refund.id}"

@tool
def execute_query(query: str) -> str:
    """Execute a raw SQL query."""
    import psycopg2
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cursor = conn.cursor()
    cursor.execute(query)
    return str(cursor.fetchall())

@tool
def web_search(query: str) -> str:
    """Search the web."""
    import requests
    response = requests.get(f"https://api.search.com/v1/search?q={query}")
    return response.text

@tool
def update_record(table: str, record_id: str, data: str) -> str:
    """Update a database record."""
    import psycopg2
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cursor = conn.cursor()
    cursor.execute(f"UPDATE {table} SET data = '{data}' WHERE id = '{record_id}'")
    conn.commit()
    return f"Updated {record_id}"

@tool
def send_slack_message(channel: str, message: str) -> str:
    """Send a Slack message."""
    from slack_sdk import WebClient
    client = WebClient(token=os.environ["SLACK_BOT_TOKEN"])
    client.chat_postMessage(channel=channel, text=message)
    return f"Sent to {channel}"

@tool
def create_ticket(title: str, body: str) -> str:
    """Create a support ticket via API."""
    import requests
    requests.post("https://api.ticketing.com/v1/tickets",
                  json={"title": title, "body": body})
    return f"Ticket created: {title}"

@tool
def generate_invoice(customer_id: str, amount: float) -> str:
    """Generate and send an invoice."""
    import requests
    requests.post("https://api.billing.com/v1/invoices",
                  json={"customer": customer_id, "amount": amount})
    return f"Invoice generated for {customer_id}"

@tool
def search_orders(customer_id: str) -> str:
    """Search customer orders."""
    import psycopg2
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM orders WHERE customer_id = '{customer_id}'")
    return str(cursor.fetchall())
