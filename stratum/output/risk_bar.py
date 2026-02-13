"""Visual risk score bar renderer."""
from __future__ import annotations

from stratum.models import Finding, Severity


def render_risk_bar(
    risk_score: int, findings: list[Finding], width: int = 40,
) -> list[str]:
    """Render a visual risk bar as a list of Rich-formatted strings.

    Output:
     RISK SCORE ████████████████████████████░░░░░░░░░░  69 / 100
                ▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔
                2 critical \u00b7 7 high \u00b7 4 medium
    """
    filled = int(width * risk_score / 100)
    empty = width - filled

    if risk_score <= 30:
        color = "green"
    elif risk_score <= 60:
        color = "yellow"
    elif risk_score <= 80:
        color = "orange1"
    else:
        color = "red"

    bar = "\u2588" * filled + "\u2591" * empty
    underline = "\u2594" * width

    # Severity counts
    sev_counts: dict[str, int] = {}
    for f in findings:
        s = f.severity.value
        sev_counts[s] = sev_counts.get(s, 0) + 1

    parts: list[str] = []
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev_counts.get(s, 0) > 0:
            parts.append(f"{sev_counts[s]} {s.lower()}")
    severity_line = " \u00b7 ".join(parts)

    return [
        "",
        f" [{color}]RISK SCORE {bar}[/{color}]  [bold]{risk_score} / 100[/bold]",
        f"            [dim]{underline}[/dim]",
        f"            {severity_line}",
        "",
    ]
