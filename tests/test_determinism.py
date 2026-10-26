"""Determinism tests: Confirm identical input produces bit-for-bit identical results."""

from pathlib import Path

from preflight.engine import PreflightEngine
from preflight.models import Environment


def test_analysis_and_scoring_determinism() -> None:
    fixture_path = Path(__file__).parent.parent / "examples" / "risky-plan.json"
    engine = PreflightEngine()

    # Run initial analysis
    first_result = engine.analyze_file(fixture_path, Environment.PRODUCTION)
    first_score = first_result.overall_risk_score
    first_findings_rules = [f.rule_id for f in first_result.findings]
    first_findings_scores = [f.calculated_score for f in first_result.findings]

    # Remove dynamic timestamp for bit-for-bit JSON comparison
    first_data = first_result.to_dict()
    first_data.pop("timestamp")

    for _ in range(50):
        run_result = engine.analyze_file(fixture_path, Environment.PRODUCTION)
        assert run_result.overall_risk_score == first_score
        assert [f.rule_id for f in run_result.findings] == first_findings_rules
        assert [f.calculated_score for f in run_result.findings] == first_findings_scores

        run_data = run_result.to_dict()
        run_data.pop("timestamp")
        assert run_data == first_data
