"""CLI integration tests covering commands, exit codes, and flag permutations."""

import json
from pathlib import Path

from typer.testing import CliRunner

from preflight.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "preflight 0.1.0" in result.stdout


def test_cli_analyze_safe_plan() -> None:
    safe_path = str(Path(__file__).parent.parent / "examples" / "safe-plan.json")
    result = runner.invoke(app, ["analyze", safe_path])
    assert result.exit_code == 0
    assert "PREFLIGHT" in result.stdout
    assert "PASSED" in result.stdout


def test_cli_analyze_risky_plan_without_policy() -> None:
    risky_path = str(Path(__file__).parent.parent / "examples" / "risky-plan.json")
    result = runner.invoke(app, ["analyze", risky_path])
    # Analysis succeeds and no fail_on policy is set -> exit code 0
    assert result.exit_code == 0
    assert "AWS-DB-001" in result.stdout


def test_cli_analyze_policy_failure() -> None:
    risky_path = str(Path(__file__).parent.parent / "examples" / "risky-plan.json")
    result = runner.invoke(app, ["analyze", risky_path, "--fail-on", "high"])
    # Policy threshold breached -> exit code 1
    assert result.exit_code == 1
    assert "DEPLOYMENT BLOCKED BY POLICY" in result.stdout


def test_cli_analyze_missing_file() -> None:
    result = runner.invoke(app, ["analyze", "non_existent_plan_file.json"])
    # File not found error -> exit code 2
    assert result.exit_code == 2
    assert "Plan Parse Error" in result.output or "not found" in result.output


def test_cli_analyze_malformed_json() -> None:
    malformed_path = str(Path(__file__).parent / "fixtures" / "plans" / "malformed.json")
    result = runner.invoke(app, ["analyze", malformed_path])
    # Syntax error -> exit code 2
    assert result.exit_code == 2
    assert "Plan Parse Error" in result.output


def test_cli_analyze_json_format() -> None:
    safe_path = str(Path(__file__).parent.parent / "examples" / "safe-plan.json")
    result = runner.invoke(app, ["analyze", safe_path, "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["environment"] == "production"
    assert "overall_risk_score" in data


def test_cli_analyze_markdown_format() -> None:
    safe_path = str(Path(__file__).parent.parent / "examples" / "safe-plan.json")
    result = runner.invoke(app, ["analyze", safe_path, "--format", "markdown"])
    assert result.exit_code == 0
    assert "# Preflight Infrastructure Risk Report" in result.stdout


def test_cli_analyze_output_file(tmp_path: Path) -> None:
    safe_path = str(Path(__file__).parent.parent / "examples" / "safe-plan.json")
    out_file = tmp_path / "report.json"
    result = runner.invoke(
        app, ["analyze", safe_path, "--format", "json", "--output", str(out_file)]
    )
    assert result.exit_code == 0
    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert "overall_risk_score" in content


def test_cli_analyze_custom_config(tmp_path: Path) -> None:
    cfg_file = tmp_path / "custom.yaml"
    cfg_file.write_text("environment: staging\nfail_on: critical\n", encoding="utf-8")
    safe_path = str(Path(__file__).parent.parent / "examples" / "safe-plan.json")

    result = runner.invoke(app, ["analyze", safe_path, "--config", str(cfg_file)])
    assert result.exit_code == 0
    assert "STAGING" in result.stdout


def test_cli_analyze_invalid_config(tmp_path: Path) -> None:
    cfg_file = tmp_path / "invalid.yaml"
    cfg_file.write_text("environment: invalid_env_name\n", encoding="utf-8")
    safe_path = str(Path(__file__).parent.parent / "examples" / "safe-plan.json")

    result = runner.invoke(app, ["analyze", safe_path, "--config", str(cfg_file)])
    assert result.exit_code == 2
    assert "Configuration Error" in result.output


def test_cli_analyze_stdin_success() -> None:
    safe_path = Path(__file__).parent.parent / "examples" / "safe-plan.json"
    content = safe_path.read_text(encoding="utf-8")
    result = runner.invoke(app, ["analyze", "-"], input=content)
    assert result.exit_code == 0
    assert "PREFLIGHT" in result.stdout
    assert "<stdin>" in result.stdout


def test_cli_analyze_stdin_policy_failure() -> None:
    risky_path = Path(__file__).parent.parent / "examples" / "risky-plan.json"
    content = risky_path.read_text(encoding="utf-8")
    result = runner.invoke(app, ["analyze", "-", "--fail-on", "high"], input=content)
    assert result.exit_code == 1
    assert "DEPLOYMENT BLOCKED BY POLICY" in result.stdout


def test_cli_analyze_stdin_empty() -> None:
    result = runner.invoke(app, ["analyze", "-"], input="")
    assert result.exit_code == 2
    assert "Standard input is empty" in result.output
