"""Generate GitHub PR comment from scan diff.

Used by the GitHub Action when running on pull_request events.
Reads GITHUB_TOKEN and PR number from environment.
"""

import json
import os
import urllib.request


def generate_comment_body(scan_result: dict, diff: dict | None) -> str:
    """Generate markdown comment body from scan result."""
    score = scan_result.get("risk_score", 0)

    # Score delta
    delta_str = ""
    if diff and diff.get("risk_score_delta", 0) != 0:
        d = diff["risk_score_delta"]
        delta_str = f" ({'+'if d > 0 else ''}{d} from main)"

    body = f"## 🔒 Stratum Security Audit\n\n"
    body += f"**Risk Score: {score}/100**{delta_str}\n\n"

    # Severity counts
    findings = scan_result.get("top_paths", []) + scan_result.get("signals", [])
    by_severity = {}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    if findings:
        body += "| Severity | Count |\n|----------|-------|\n"
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in by_severity:
                body += f"| {sev} | {by_severity[sev]} |\n"
        body += "\n"

    # New findings
    if diff and diff.get("new_finding_ids"):
        body += "**New findings in this PR:**\n\n"
        for fid in diff["new_finding_ids"][:3]:  # max 3
            for f in findings:
                if f.get("id") == fid:
                    body += f"- **{f['id']}** \u00b7 {f.get('owasp_id', '')} \u2014 {f.get('title', '')}\n"
        body += "\n"

    if not findings:
        body += "\u2705 No findings detected.\n\n"

    body += "*Run `stratum scan .` locally for full details.*\n"
    return body


def post_comment(body: str):
    """Post comment to GitHub PR using GITHUB_TOKEN."""
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    event_path = os.environ.get("GITHUB_EVENT_PATH")

    if not all([token, repo, event_path]):
        return

    with open(event_path) as f:
        event = json.load(f)

    pr_number = event.get("pull_request", {}).get("number")
    if not pr_number:
        return

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": body}).encode()

    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
    })

    urllib.request.urlopen(req)
