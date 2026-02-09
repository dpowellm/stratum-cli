"""Generate README badge for Stratum scan results.

Uses shields.io static badge URLs -- no Stratum backend needed.
The badge is a URL string the developer pastes into their README.
"""


def generate_badge_markdown(score: int) -> str:
    """Generate a shields.io badge markdown string.

    Score 0-30: green
    Score 31-60: yellow
    Score 61-100: red
    """
    color = "brightgreen" if score <= 30 else "yellow" if score <= 60 else "red"
    return f"![Stratum Risk Score](https://img.shields.io/badge/stratum_risk-{score}%2F100-{color})"


def generate_badge_url(score: int) -> str:
    """Just the URL, no markdown wrapping."""
    color = "brightgreen" if score <= 30 else "yellow" if score <= 60 else "red"
    return f"https://img.shields.io/badge/stratum_risk-{score}%2F100-{color}"
