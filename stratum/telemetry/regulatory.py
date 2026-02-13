"""Regulatory exposure computation for ScanProfile."""
from __future__ import annotations


def compute_regulatory_exposure(
    *,
    has_financial_tools: bool = False,
    has_credential_flow: bool = False,
    has_pii_flow: bool = False,
    has_observability: bool = False,
    has_structured_output: bool = False,
    has_hitl: bool = False,
    has_no_error_handling: bool = False,
    has_input_validation: bool = False,
    has_no_audit_trail: bool = False,
    uncontrolled_path_count: int = 0,
    maturity_score: int = 0,
) -> dict:
    """Map data flows and control states to specific regulatory requirements.

    Returns dict with: applicable_regulations, eu_ai_act_risk_level,
    eu_ai_act_articles, eu_ai_act_gap_count, gdpr_relevant, gdpr_articles,
    nist_ai_rmf_functions, compliance_gap_count.
    """
    result: dict = {
        "applicable_regulations": [],
        "eu_ai_act_risk_level": "unknown",
        "eu_ai_act_articles": [],
        "eu_ai_act_gap_count": 0,
        "gdpr_relevant": False,
        "gdpr_articles": [],
        "nist_ai_rmf_functions": [],
        "compliance_gap_count": 0,
    }

    # ── EU AI Act ──

    # Risk level classification
    if has_financial_tools or has_credential_flow:
        result["eu_ai_act_risk_level"] = "high"
    elif has_pii_flow:
        result["eu_ai_act_risk_level"] = "limited"
    else:
        result["eu_ai_act_risk_level"] = "minimal"

    gaps = 0

    # Art. 9 — Risk management system
    result["eu_ai_act_articles"].append("Art.9")
    if not has_observability and not has_structured_output:
        gaps += 1  # No systematic risk identification

    # Art. 14 — Human oversight
    result["eu_ai_act_articles"].append("Art.14")
    if not has_hitl:
        gaps += 1

    # Art. 15 — Accuracy, robustness, cybersecurity
    result["eu_ai_act_articles"].append("Art.15")
    if has_no_error_handling or not has_input_validation:
        gaps += 1

    # Art. 13 — Transparency and information to deployers
    if not has_observability:
        result["eu_ai_act_articles"].append("Art.13")
        gaps += 1

    # Art. 12 — Record-keeping
    if has_no_audit_trail:
        result["eu_ai_act_articles"].append("Art.12")
        gaps += 1

    result["eu_ai_act_gap_count"] = gaps
    result["applicable_regulations"].append("EU_AI_ACT")

    # ── GDPR ──

    if has_pii_flow:
        result["gdpr_relevant"] = True
        result["applicable_regulations"].append("GDPR")

        # Art. 35 — DPIA required for high-risk processing
        if uncontrolled_path_count > 0:
            result["gdpr_articles"].append("Art.35")
            gaps += 1

        # Art. 22 — Automated decision-making
        if not has_hitl:
            result["gdpr_articles"].append("Art.22")
            gaps += 1

    # ── NIST AI RMF ──

    result["applicable_regulations"].append("NIST_AI_RMF")

    if has_observability:
        result["nist_ai_rmf_functions"].append("MEASURE")
    if has_hitl or has_structured_output:
        result["nist_ai_rmf_functions"].append("MANAGE")
    if maturity_score > 40:
        result["nist_ai_rmf_functions"].append("GOVERN")
    # MAP is always applicable
    result["nist_ai_rmf_functions"].append("MAP")

    result["compliance_gap_count"] = gaps

    return result
