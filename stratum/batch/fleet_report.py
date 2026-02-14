"""Enterprise fleet report generator.

Generates a fleet assessment from batch scan profiles for a specific company.
Output: HTML report (printable to PDF) or JSON data structure.

Usage:
    python -m stratum.batch.fleet_report --org acme --profiles-dir ./scans/ --output acme-fleet.html
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from collections import Counter
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def generate_fleet_report(
    org_id: str,
    profiles_dir: str,
    output_path: str | None = None,
) -> dict:
    """Generate an enterprise fleet assessment for a specific organization.

    Args:
        org_id: Organization identifier to filter profiles by.
        profiles_dir: Directory containing batch scan profile JSONs.
        output_path: If provided, write HTML report to this path.

    Returns:
        Dict with all fleet assessment data.
    """
    # Load profiles for this org
    profiles = _load_org_profiles(org_id, profiles_dir)
    if not profiles:
        logger.warning("No profiles found for org: %s", org_id)
        return {"error": f"No profiles found for org: {org_id}"}

    report = _build_report_data(org_id, profiles)

    if output_path:
        if output_path.endswith(".html"):
            html = _render_html(report)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)
            logger.info("Fleet report written to %s", output_path)
        else:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            logger.info("Fleet report JSON written to %s", output_path)

    return report


def _load_org_profiles(org_id: str, profiles_dir: str) -> list[dict]:
    """Load all profiles belonging to an organization."""
    profiles = []
    org_lower = org_id.lower()

    for fname in os.listdir(profiles_dir):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(profiles_dir, fname), "r", encoding="utf-8") as f:
                data = json.load(f)
            profile = data.get("scan_profile", data)
            profile_org = (
                profile.get("org_id", "")
                or profile.get("_batch", {}).get("org", "")
            )
            if profile_org.lower() == org_lower:
                profiles.append(profile)
        except (OSError, json.JSONDecodeError):
            continue

    return profiles


def _build_report_data(org_id: str, profiles: list[dict]) -> dict:
    """Build the fleet assessment data structure."""
    now = datetime.now(timezone.utc).strftime("%B %Y")

    # Aggregate metrics
    total_agents = sum(p.get("agent_count", 0) for p in profiles)
    total_crews = sum(p.get("crew_count", 0) for p in profiles)
    total_findings = sum(p.get("finding_count", 0) for p in profiles)
    risk_scores = [p.get("risk_score", 0) for p in profiles]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0
    max_risk = max(risk_scores) if risk_scores else 0

    # Framework distribution
    all_frameworks: list[str] = []
    for p in profiles:
        all_frameworks.extend(p.get("frameworks", []))
    fw_counts = dict(Counter(all_frameworks))

    # Model dependency
    all_models: list[str] = []
    for p in profiles:
        for m in p.get("llm_models", []):
            if isinstance(m, dict):
                all_models.append(m.get("model", "unknown"))
    model_counts = dict(Counter(all_models))

    # Provider concentration
    all_providers: list[str] = []
    for p in profiles:
        for m in p.get("llm_models", []):
            if isinstance(m, dict):
                all_providers.append(m.get("provider", "unknown"))
    provider_counts = dict(Counter(all_providers))

    # Severity distribution across fleet
    severity_totals: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for p in profiles:
        fbs = p.get("findings_by_severity", {})
        for sev, count in fbs.items():
            severity_totals[sev] = severity_totals.get(sev, 0) + count
    critical_count = severity_totals.get("critical", 0) + severity_totals.get("high", 0)

    # Projects with critical findings
    critical_projects = sum(
        1 for p in profiles
        if p.get("findings_by_severity", {}).get("high", 0) > 0
        or p.get("findings_by_severity", {}).get("critical", 0) > 0
    )

    # Breach pattern matches
    breach_matches = 0
    for p in profiles:
        if p.get("matches_any_breach", False):
            breach_matches += 1

    # Maturity scores
    maturity_scores = [p.get("maturity_score", 0) for p in profiles]
    avg_maturity = round(sum(maturity_scores) / len(maturity_scores), 1) if maturity_scores else 0

    # Shared services (specific env vars across projects)
    shared_services: dict[str, int] = {}
    for p in profiles:
        for env in p.get("env_var_names_specific", []):
            if isinstance(env, dict):
                name = env.get("name", "")
                shared_services[name] = shared_services.get(name, 0) + 1
    cross_project_services = {k: v for k, v in shared_services.items() if v >= 2}

    # Top risk: provider concentration
    top_risk = ""
    if provider_counts:
        dominant = max(provider_counts, key=provider_counts.get)
        dominant_pct = round(provider_counts[dominant] * 100 / sum(provider_counts.values()))
        if dominant_pct > 60:
            top_risk = (
                f"{sum(1 for p in profiles if any(m.get('provider') == dominant for m in p.get('llm_models', []) if isinstance(m, dict)))} "
                f"of {len(profiles)} projects depend on {dominant}. "
                f"Single-provider outage affects {dominant_pct}% of your AI fleet."
            )

    # What-if: best single action
    top_action = ""
    action_impact = 0
    for p in profiles:
        for ctrl in p.get("what_if_controls", []):
            if isinstance(ctrl, dict) and ctrl.get("score_reduction", 0) > action_impact:
                action_impact = ctrl["score_reduction"]
                top_action = ctrl.get("description", "")

    # Per-project table
    project_table = []
    for p in profiles:
        project_table.append({
            "name": p.get("project_name", "unknown"),
            "risk_score": p.get("risk_score", 0),
            "frameworks": p.get("frameworks", []),
            "finding_count": p.get("finding_count", 0),
            "maturity": p.get("maturity_level", "unknown"),
            "agent_count": p.get("agent_count", 0),
        })
    project_table.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "org_id": org_id,
        "generated_at": now,
        "project_count": len(profiles),
        "total_agents": total_agents,
        "total_crews": total_crews,
        "total_findings": total_findings,
        "framework_counts": fw_counts,
        "risk_scores": risk_scores,
        "avg_risk": avg_risk,
        "max_risk": max_risk,
        "critical_findings": critical_count,
        "critical_projects": critical_projects,
        "breach_matches": breach_matches,
        "model_counts": model_counts,
        "provider_counts": provider_counts,
        "severity_totals": severity_totals,
        "avg_maturity": avg_maturity,
        "cross_project_services": cross_project_services,
        "top_risk": top_risk,
        "top_action": top_action,
        "top_action_impact": action_impact,
        "project_table": project_table,
    }


def _render_html(report: dict) -> str:
    """Render the fleet report as a self-contained HTML document."""
    org = report["org_id"]
    date = report["generated_at"]
    projects = report["project_count"]
    agents = report["total_agents"]
    frameworks = ", ".join(report["framework_counts"].keys())
    avg_risk = report["avg_risk"]
    critical = report["critical_findings"]
    breaches = report["breach_matches"]
    top_risk = report.get("top_risk", "")
    top_action = report.get("top_action", "")

    # Project table rows
    rows = ""
    for p in report["project_table"]:
        fw = ", ".join(p["frameworks"])
        risk_class = "high" if p["risk_score"] >= 70 else ("medium" if p["risk_score"] >= 40 else "low")
        rows += (
            f"<tr><td>{p['name']}</td><td class='{risk_class}'>{p['risk_score']}</td>"
            f"<td>{fw}</td><td>{p['finding_count']}</td>"
            f"<td>{p['maturity']}</td><td>{p['agent_count']}</td></tr>\n"
        )

    # Model dependency section
    model_rows = ""
    for model, count in sorted(report["model_counts"].items(), key=lambda x: -x[1]):
        model_rows += f"<tr><td>{model}</td><td>{count}</td></tr>\n"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{org} — AI Agent Fleet Assessment</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; }}
  h1 {{ border-bottom: 3px solid #2563eb; padding-bottom: 12px; }}
  .summary {{ background: #f0f4ff; border: 1px solid #2563eb; border-radius: 8px; padding: 24px; margin: 24px 0; }}
  .summary h2 {{ margin-top: 0; color: #2563eb; }}
  .metric {{ display: inline-block; margin-right: 32px; }}
  .metric .value {{ font-size: 28px; font-weight: bold; color: #2563eb; }}
  .metric .label {{ font-size: 13px; color: #666; }}
  .alert {{ background: #fef2f2; border-left: 4px solid #dc2626; padding: 12px 16px; margin: 16px 0; }}
  .action {{ background: #f0fdf4; border-left: 4px solid #16a34a; padding: 12px 16px; margin: 16px 0; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  th {{ text-align: left; background: #f8fafc; padding: 8px; border-bottom: 2px solid #e2e8f0; font-size: 13px; }}
  td {{ padding: 8px; border-bottom: 1px solid #e2e8f0; }}
  .high {{ color: #dc2626; font-weight: bold; }}
  .medium {{ color: #d97706; }}
  .low {{ color: #16a34a; }}
  .footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #999; }}
  @media print {{ .summary {{ break-inside: avoid; }} }}
</style>
</head>
<body>

<h1>{org} — AI Agent Fleet Assessment</h1>
<p style="color: #666">{date}</p>

<div class="summary">
  <h2>Fleet Overview</h2>
  <div class="metric"><div class="value">{projects}</div><div class="label">Agent Projects</div></div>
  <div class="metric"><div class="value">{agents}</div><div class="label">Total Agents</div></div>
  <div class="metric"><div class="value">{avg_risk}/100</div><div class="label">Avg Risk Score</div></div>
  <div class="metric"><div class="value">{critical}</div><div class="label">Critical+High Findings</div></div>
  <div class="metric"><div class="value">{breaches}</div><div class="label">Breach Pattern Matches</div></div>
  <p><strong>Frameworks:</strong> {frameworks}</p>
</div>

{"<div class='alert'><strong>TOP RISK:</strong> " + top_risk + "</div>" if top_risk else ""}
{"<div class='action'><strong>TOP ACTION:</strong> " + top_action + " (reduces risk by " + str(report.get('top_action_impact', 0)) + " points)</div>" if top_action else ""}

<h2>Project Risk Table</h2>
<table>
<tr><th>Project</th><th>Risk</th><th>Framework</th><th>Findings</th><th>Maturity</th><th>Agents</th></tr>
{rows}
</table>

<h2>Model Dependencies</h2>
<table>
<tr><th>Model</th><th>Projects Using</th></tr>
{model_rows}
</table>

<div class="footer">
  <p>Generated by Stratum · stratum.dev</p>
  <p>This assessment is based on static analysis of public repositories. Runtime behavior may differ.
  For live monitoring, contact us about Stratum Enterprise.</p>
</div>

</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate enterprise fleet report")
    parser.add_argument("--org", type=str, required=True, help="Organization ID")
    parser.add_argument("--profiles-dir", type=str, required=True,
                        help="Directory with batch scan profiles")
    parser.add_argument("--output", type=str, help="Output file (HTML or JSON)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(message)s",
    )

    report = generate_fleet_report(args.org, args.profiles_dir, args.output)
    if not args.output:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
