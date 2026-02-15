"""Tests for compound risk scoring with toxic combinations."""
import pytest

from stratum.models import Finding, Severity, Confidence, RiskCategory, TCMatch
from stratum.scanner import (
    calculate_risk_score,
    compute_compound_risk_score,
    TC_SEVERITY_WEIGHTS,
    COMPONENT_MULTIPLIER,
)


# ── Helpers ─────────────────────────────────────────────────────────


def make_finding(rule_id: str, severity: Severity, finding_class: str = "architecture") -> Finding:
    """Create a minimal Finding for scoring tests."""
    return Finding(
        id=rule_id,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        category=RiskCategory.SECURITY,
        title=f"Test finding {rule_id}",
        path="test.py",
        description="Test description",
        finding_class=finding_class,
    )


def make_tc_match(
    tc_id: str,
    severity: str,
    components: list[str],
) -> TCMatch:
    """Create a minimal TCMatch for scoring tests."""
    return TCMatch(
        tc_id=tc_id,
        name=f"Test TC {tc_id}",
        severity=severity,
        description="Test TC description",
        finding_components=components,
        owasp_ids=[],
        matched_nodes={},
        matched_edges=[],
        matched_path=[],
        remediation={},
    )


# ── Tests ───────────────────────────────────────────────────────────


def test_base_score_unchanged_no_tcs():
    """Without TCs, compound score equals base score."""
    findings = [
        make_finding("STRATUM-001", Severity.HIGH),
        make_finding("STRATUM-002", Severity.MEDIUM),
    ]
    base_score = calculate_risk_score(findings)

    compound = compute_compound_risk_score(findings, [], base_score)
    assert compound == base_score


def test_compound_score_higher_with_tcs():
    """With TCs, compound score > base score."""
    findings = [
        make_finding("STRATUM-002", Severity.HIGH),
        make_finding("STRATUM-005", Severity.MEDIUM),
    ]
    base_score = calculate_risk_score(findings)

    tc = make_tc_match("STRATUM-TC-001", "CRITICAL", ["STRATUM-002", "STRATUM-005"])
    compound = compute_compound_risk_score(findings, [tc], base_score)

    assert compound > base_score, f"Compound {compound} should be > base {base_score}"


def test_compound_score_capped_at_100():
    """Even with many TCs, score never exceeds 100."""
    findings = [
        make_finding("STRATUM-001", Severity.CRITICAL),
        make_finding("STRATUM-002", Severity.CRITICAL),
        make_finding("STRATUM-003", Severity.CRITICAL),
        make_finding("STRATUM-005", Severity.CRITICAL),
    ]
    base_score = calculate_risk_score(findings)

    # Add many TCs
    tcs = [
        make_tc_match("STRATUM-TC-001", "CRITICAL", ["STRATUM-002", "STRATUM-005"]),
        make_tc_match("STRATUM-TC-002", "CRITICAL", ["STRATUM-001"]),
        make_tc_match("STRATUM-TC-003", "CRITICAL", ["STRATUM-003"]),
        make_tc_match("STRATUM-TC-004", "CRITICAL", ["STRATUM-001", "STRATUM-002", "STRATUM-005"]),
        make_tc_match("STRATUM-TC-005", "CRITICAL", ["STRATUM-001"]),
    ]
    compound = compute_compound_risk_score(findings, tcs, base_score)
    assert compound <= 100, f"Compound score {compound} should not exceed 100"


def test_compound_score_never_below_base():
    """Compound score >= base score always."""
    findings = [
        make_finding("STRATUM-001", Severity.MEDIUM),
    ]
    base_score = calculate_risk_score(findings)

    tc = make_tc_match("STRATUM-TC-001", "MEDIUM", ["STRATUM-001"])
    compound = compute_compound_risk_score(findings, [tc], base_score)
    assert compound >= base_score, f"Compound {compound} should be >= base {base_score}"


def test_double_count_deduction():
    """Verify partial deduction for overlapping finding components."""
    findings = [
        make_finding("STRATUM-002", Severity.HIGH),
        make_finding("STRATUM-005", Severity.MEDIUM),
    ]
    base_score = calculate_risk_score(findings)

    # TC with components that overlap with existing findings
    tc = make_tc_match("STRATUM-TC-001", "CRITICAL", ["STRATUM-002", "STRATUM-005"])
    compound = compute_compound_risk_score(findings, [tc], base_score)

    # The compound score should be less than base + full CRITICAL weight (20)
    # because of the 50% double-count deduction
    max_possible = base_score + TC_SEVERITY_WEIGHTS["CRITICAL"]
    assert compound < max_possible or compound == 100, \
        f"Double-count deduction should reduce score below {max_possible}"


def test_critical_tc_weight():
    """CRITICAL TC adds 20 base points (before deductions)."""
    assert TC_SEVERITY_WEIGHTS["CRITICAL"] == 20
    assert TC_SEVERITY_WEIGHTS["HIGH"] == 12
    assert TC_SEVERITY_WEIGHTS["MEDIUM"] == 6


def test_component_multiplier():
    """TC with 3 components has a higher multiplier than TC with 2 components.

    The COMPONENT_MULTIPLIER adds +20% per component beyond 2, so
    a 3-component TC has multiplier 1.2 vs 1.0 for 2-component.
    We verify this by using non-overlapping findings to avoid
    double-count deduction masking the multiplier effect.
    """
    # Use findings that are NOT in the component list to avoid deduction effects
    findings = [
        make_finding("STRATUM-008", Severity.MEDIUM, "operational"),
    ]
    base_score = calculate_risk_score(findings)

    # TC with 2 non-overlapping components: weight * 1.0
    tc_2 = make_tc_match("STRATUM-TC-001", "HIGH", ["STRATUM-002", "STRATUM-005"])
    compound_2 = compute_compound_risk_score(findings, [tc_2], base_score)

    # TC with 3 non-overlapping components: weight * 1.2
    tc_3 = make_tc_match("STRATUM-TC-001", "HIGH", ["STRATUM-001", "STRATUM-002", "STRATUM-005"])
    compound_3 = compute_compound_risk_score(findings, [tc_3], base_score)

    assert compound_3 > compound_2, \
        f"TC with 3 components ({compound_3}) should add more than TC with 2 ({compound_2})"
    # Verify the multiplier math: HIGH weight is 12, multiplier diff is 0.2
    assert compound_3 - compound_2 == int(12 * 0.2), \
        f"Expected {int(12 * 0.2)} point difference from multiplier"
