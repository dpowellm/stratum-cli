"""Bordered code snippet renderer."""
from __future__ import annotations


def render_code_block(code: str, max_width: int = 60) -> str:
    """Render code in a bordered box.

    Output:
       \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
       \u2502  task = Task(                                          \u2502
       \u2502      description="...",                                \u2502
       \u2502 +    human_input=True   # review before external calls \u2502
       \u2502  )                                                     \u2502
       \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518
    """
    lines = code.strip().split("\n")
    inner_width = max(len(line) for line in lines) + 2
    inner_width = max(inner_width, 20)
    inner_width = min(inner_width, max_width - 4)

    result = [f"   \u250c{'\u2500' * (inner_width + 2)}\u2510"]
    for line in lines:
        padded = line[:inner_width].ljust(inner_width)
        result.append(f"   \u2502 {padded} \u2502")
    result.append(f"   \u2514{'\u2500' * (inner_width + 2)}\u2518")

    return "\n".join(result)
