"""Generate README badge for Stratum scan results.

Supports shields.io URLs and local SVG generation.
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


def _score_color(score: int) -> str:
    """Map risk score to badge color hex."""
    if score <= 30:
        return "#4c1"
    elif score <= 60:
        return "#dfb317"
    elif score <= 80:
        return "#fe7d37"
    else:
        return "#e05d44"


def generate_badge_svg(score: int, finding_count: int = 0) -> str:
    """Generate a shields.io-compatible SVG badge for local embedding.

    Format: "stratum | risk: 65 · 5 findings"
    """
    color = _score_color(score)
    right_text = f"risk: {score}"
    if finding_count > 0:
        right_text += f" / {finding_count} findings"

    left_width = 52
    right_width = 14 + len(right_text) * 6.5
    total_width = left_width + right_width

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_width:.0f}" height="20" role="img">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="{total_width:.0f}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{left_width}" height="20" fill="#555"/>
    <rect x="{left_width}" width="{right_width:.0f}" height="20" fill="{color}"/>
    <rect width="{total_width:.0f}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="{left_width / 2:.0f}" y="15" fill="#010101" fill-opacity=".3">stratum</text>
    <text x="{left_width / 2:.0f}" y="14">stratum</text>
    <text x="{left_width + right_width / 2:.0f}" y="15" fill="#010101" fill-opacity=".3">{right_text}</text>
    <text x="{left_width + right_width / 2:.0f}" y="14">{right_text}</text>
  </g>
</svg>'''
