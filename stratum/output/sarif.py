"""Generate SARIF 2.1.0 output from Stratum scan results."""
from __future__ import annotations

from stratum.models import Finding, ScanResult, Severity


SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def generate_sarif(result: ScanResult) -> dict:
    """Produce a SARIF 2.1.0 compliant dict from a ScanResult."""
    all_findings = result.top_paths + result.signals

    # Build rules (deduplicated by finding ID)
    rules_by_id: dict[str, dict] = {}
    for finding in all_findings:
        if finding.id not in rules_by_id:
            rules_by_id[finding.id] = _finding_to_rule(finding)

    rules = list(rules_by_id.values())
    rule_index = {rule_id: i for i, rule_id in enumerate(rules_by_id.keys())}

    # Build results
    results = []
    for finding in all_findings:
        results.append(_finding_to_result(finding, rule_index))

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Stratum",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/stratum-systems/stratum-cli",
                        "rules": rules,
                    },
                },
                "results": results,
            }
        ],
    }


def _finding_to_rule(finding: Finding) -> dict:
    """Convert a Finding into a SARIF reportingDescriptor (rule)."""
    rule: dict = {
        "id": finding.id,
        "name": finding.title.replace(" ", ""),
        "shortDescription": {"text": finding.title},
        "defaultConfiguration": {
            "level": SARIF_LEVEL.get(finding.severity, "warning"),
        },
    }

    if finding.description:
        rule["fullDescription"] = {"text": finding.description}

    if finding.references:
        rule["helpUri"] = finding.references[0]

    tags = []
    if finding.owasp_id:
        tags.append(finding.owasp_id)
    if finding.owasp_name:
        tags.append(finding.owasp_name)
    tags.append("ai-agent")
    tags.append("security")
    rule["properties"] = {"tags": tags}

    return rule


def _finding_to_result(finding: Finding, rule_index: dict[str, int]) -> dict:
    """Convert a Finding into a SARIF result."""
    result: dict = {
        "ruleId": finding.id,
        "ruleIndex": rule_index.get(finding.id, 0),
        "level": SARIF_LEVEL.get(finding.severity, "warning"),
        "message": {
            "text": finding.scenario or finding.description or finding.title,
        },
    }

    location = _extract_location(finding)
    if location:
        result["locations"] = [location]

    return result


def _extract_location(finding: Finding) -> dict | None:
    """Extract a SARIF location from finding evidence.

    Evidence strings are in format "file.py:42" or just "file.py".
    """
    for ev in finding.evidence:
        if ":" in ev and ev.rsplit(":", 1)[-1].isdigit():
            parts = ev.rsplit(":", 1)
            return {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": parts[0].replace("\\", "/"),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": int(parts[1])},
                },
            }
        if ev.endswith(".py"):
            return {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": ev.replace("\\", "/"),
                        "uriBaseId": "%SRCROOT%",
                    },
                },
            }
    return None
