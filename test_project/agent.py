"""Customer support agent with terrible security practices."""
import os
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver

from tools import (get_customer_data, send_email, delete_record,
                   run_shell_command, process_refund, execute_query,
                   web_search, update_record, create_ticket,
                   send_slack_message, generate_invoice, search_orders)

def create_agent():
    """Create agent with no guardrails, no interrupt_before, MemorySaver only."""
    llm = ChatOpenAI(model="gpt-4o", temperature=0.8)
    tools = [get_customer_data, send_email, delete_record,
             run_shell_command, process_refund, execute_query,
             web_search, update_record, create_ticket,
             send_slack_message, generate_invoice, search_orders]

    tool_node = ToolNode(tools)
    workflow = StateGraph(dict)
    workflow.add_node("agent", lambda state: state)
    workflow.add_node("tools", tool_node)
    workflow.set_entry_point("agent")
    workflow.add_edge("agent", "tools")
    workflow.add_edge("tools", END)
    checkpointer = MemorySaver()
    graph = workflow.compile(checkpointer=checkpointer)
    # NOTE: no interrupt_before, no guardrails
    return graph
