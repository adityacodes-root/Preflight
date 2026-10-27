"""Tests for the reporting layer (Terminal, JSON, Markdown)."""

import json
from pathlib import Path

from preflight.engine import PreflightEngine
from preflight.models import Environment
from preflight.reporting import (
    PR_COMMENT_MARKER,
    get_terminal_report_str,
    render_json_report,
    render_markdown_report,
    render_pr_comment,
    render_sarif_report,
)


def test_terminal_report_output() -> None:
    fixture_path = Path(__file__).parent.parent / "examples" / "risky-plan.json"
    engine = PreflightEngine()
    result = engine.analyze_file(fixture_path, Environment.PRODUCTION)

    output = get_terminal_report_str(result)
    assert "PREFLIGHT: Infrastructure Change Risk Analysis" in output
    assert "Planned Resource Operations" in output
    assert "AWS-DB-001" in output
    assert "AWS-NET-001" in output
    assert "Risk Factor Breakdown" in output
    assert "Change Impact" in output


def test_json_report_structure() -> None:
    fixture_path = Path(__file__).parent.parent / "examples" / "risky-plan.json"
    engine = PreflightEngine()
    result = engine.analyze_file(fixture_path, Environment.PRODUCTION)

    json_str = render_json_report(result)
    data = json.loads(json_str)

    assert "plan_path" in data
    assert "environment" in data
    assert data["environment"] == "production"
    assert "overall_risk_score" in data
    assert data["overall_risk_score"] > 75.0
    assert data["overall_risk_category"] == "critical"
    assert "summary" in data
    assert "findings" in data
    assert len(data["findings"]) > 0

    finding = data["findings"][0]
    assert "rule_id" in finding
    assert "risk_factors" in finding
    assert "change_impact" in finding["risk_factors"]
    assert "remediation" in finding


def test_markdown_report_structure() -> None:
    fixture_path = Path(__file__).parent.parent / "examples" / "risky-plan.json"
    engine = PreflightEngine()
    result = engine.analyze_file(fixture_path, Environment.PRODUCTION)

    md = render_markdown_report(result)
    assert "# Preflight Infrastructure Risk Report" in md
    assert "## Overview" in md
    assert "| **Overall Risk Score** |" in md
    assert "### Planned Operations" in md
    assert "## Risk Findings" in md
    assert "AWS-DB-001" in md
    assert "### 1. [" in md


def test_sarif_report_structure() -> None:
    fixture_path = Path(__file__).parent.parent / "examples" / "risky-plan.json"
    engine = PreflightEngine()
    result = engine.analyze_file(fixture_path, Environment.PRODUCTION)

    sarif_str = render_sarif_report(result)
    sarif = json.loads(sarif_str)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Preflight"
    assert len(run["tool"]["driver"]["rules"]) > 0
    assert len(run["results"]) == len(result.findings)

    first_result = run["results"][0]
    assert "ruleId" in first_result
    assert "level" in first_result
    assert first_result["level"] in ("error", "warning", "note")
    assert len(first_result["locations"]) > 0


def test_sarif_report_empty_findings() -> None:
    fixture_path = Path(__file__).parent.parent / "examples" / "safe-plan.json"
    engine = PreflightEngine()
    result = engine.analyze_file(fixture_path, Environment.PRODUCTION)

    sarif_str = render_sarif_report(result)
    sarif = json.loads(sarif_str)
    assert len(sarif["runs"][0]["results"]) == 0


def test_pr_comment_structure() -> None:
    fixture_path = Path(__file__).parent.parent / "examples" / "risky-plan.json"
    engine = PreflightEngine()
    result = engine.analyze_file(fixture_path, Environment.PRODUCTION)

    comment = render_pr_comment(result)
    assert PR_COMMENT_MARKER in comment
    assert "## Preflight Infrastructure Risk Analysis" in comment
    assert "**CRITICAL**" in comment
    assert "### Planned Resource Operations" in comment
    assert "<details" in comment
    assert "<summary>" in comment
    assert "AWS-DB-001" in comment
