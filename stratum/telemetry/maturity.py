"""Maturity score computation for ScanProfile."""
from __future__ import annotations


def compute_maturity_score(
    *,
    has_hitl: bool = False,
    has_structured_output: bool = False,
    has_observability: bool = False,
    has_error_handling: bool = False,
    error_handling_ratio: float = 0.0,
    checkpoint_type: str = "none",
    has_checkpointing: bool = False,
    has_input_validation: bool = False,
    has_rate_limiting: bool = False,
    has_output_filtering: bool = False,
    guardrail_coverage_ratio: float = 0.0,
) -> tuple[int, str]:
    """Weighted composite of control signals.

    Returns (score 0-100, level label).

    Weights reflect what actually reduces risk based on ecosystem data.
    Initially set by judgment; recalibrated once N > 5000 using actual
    risk score correlations.
    """
    score = 0

    # Human oversight (most impactful)
    if has_hitl:
        score += 25

    # Output validation (prevents hallucination propagation)
    if has_structured_output:
        score += 15

    # Observability (can't fix what you can't see)
    if has_observability:
        score += 15

    # Error handling (resilience)
    if has_error_handling:
        score += 10
    elif error_handling_ratio > 0:
        score += int(10 * error_handling_ratio)

    # Checkpointing (recovery)
    if checkpoint_type == "durable":
        score += 10
    elif has_checkpointing:
        score += 5

    # Input validation on tools
    if has_input_validation:
        score += 10

    # Rate limiting (cost control, runaway prevention)
    if has_rate_limiting:
        score += 5

    # Output filtering (content safety)
    if has_output_filtering:
        score += 5

    # Guardrail coverage (are guardrails actually connected?)
    if guardrail_coverage_ratio > 0.5:
        score += 5
    elif guardrail_coverage_ratio > 0:
        score += 2

    score = min(score, 100)

    if score <= 20:
        level = "none"
    elif score <= 40:
        level = "basic"
    elif score <= 60:
        level = "developing"
    elif score <= 80:
        level = "established"
    else:
        level = "advanced"

    return score, level
