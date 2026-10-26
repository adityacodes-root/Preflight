"""Reporting layer: Renders terminal, JSON, and Markdown reports."""

import json
from io import StringIO
from typing import TextIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from preflight.models import (
    AnalysisResult,
    RiskCategory,
    Severity,
)

# Color palettes for severities and risk bands
SEVERITY_STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MODERATE: "bold yellow",
    Severity.LOW: "bold cyan",
}

RISK_CATEGORY_STYLES = {
    RiskCategory.CRITICAL: "bold red",
    RiskCategory.HIGH: "bold orange3",
    RiskCategory.MODERATE: "bold yellow",
    RiskCategory.LOW: "bold green",
}


def render_terminal_report(result: AnalysisResult, file: TextIO | None = None) -> None:
    """Render a clean, human-readable terminal report with Rich."""
    console = Console(file=file, highlight=False, force_terminal=False if file else None)

    # 1. Header Banner
    cat_style = RISK_CATEGORY_STYLES.get(result.overall_risk_category, "bold white")
    score_text = (
        f"{result.overall_risk_score:.1f} / 100 ({result.overall_risk_category.value.upper()})"
    )

    header_text = Text()
    header_text.append("PREFLIGHT: Infrastructure Change Risk Analysis\n", style="bold cyan")
    header_text.append(f"Plan:        {result.plan_path}\n", style="dim")
    header_text.append(f"Environment: {result.environment.value.upper()}\n", style="dim")
    header_text.append("Risk Score:  ")
    header_text.append(score_text, style=cat_style)

    console.print(Panel(header_text, border_style="dim", expand=False))

    # 2. Plan Actions Summary Table
    summary = result.summary
    summary_table = Table(title="Planned Resource Operations", border_style="dim", show_header=True)
    summary_table.add_column("Create", style="green", justify="center")
    summary_table.add_column("Update", style="yellow", justify="center")
    summary_table.add_column("Delete", style="red", justify="center")
    summary_table.add_column("Replace", style="bold red", justify="center")
    summary_table.add_column("Read / No-op", style="dim", justify="center")
    summary_table.add_column("Unknown Actions", style="magenta", justify="center")

    summary_table.add_row(
        str(summary.to_create),
        str(summary.to_update),
        str(summary.to_delete),
        str(summary.to_replace),
        f"{summary.to_read} / {summary.to_noop}",
        str(summary.unknown_actions),
    )
    console.print(summary_table)

    # 3. Findings Section
    if not result.findings:
        console.print(
            "\n[bold green][PASS] No risk findings detected.[/bold green] Infrastructure changes appear safe.\n"
        )
    else:
        console.print(f"\n[bold]Risk Findings ({len(result.findings)}):[/bold]\n")

        for idx, finding in enumerate(result.findings, start=1):
            sev_style = SEVERITY_STYLES.get(finding.severity, "bold white")
            f_title = Text()
            f_title.append(f"#{idx} [{finding.rule_id}] ", style="bold")
            f_title.append(f" {finding.severity.value.upper()} ", style=sev_style)
            f_title.append(f"  {finding.rule_name}  (Score: {finding.calculated_score:.1f})")

            body = Text()
            body.append("Resource:    ", style="bold")
            body.append(f"{finding.resource_address} ({finding.resource_type})\n")
            body.append("Action:      ", style="bold")
            body.append(f"{finding.action.value.upper()}\n\n")

            body.append("What changed:\n", style="bold")
            body.append(f"  {finding.what_changed}\n\n")

            body.append("Why it matters:\n", style="bold")
            body.append(f"  {finding.why_it_matters}\n\n")

            # Risk factors breakdown
            rf = finding.risk_factors
            body.append("Risk Factor Breakdown:\n", style="bold")
            body.append(
                f"  Change Impact: {rf.change_impact:.1f}/5  |  "
                f"Security Exposure: {rf.security_exposure:.1f}/5  |  "
                f"Reversibility: {rf.reversibility:.1f}/5\n"
                f"  Env Criticality: {rf.environment_criticality:.1f}/5  |  "
                f"Uncertainty: {rf.uncertainty:.1f}/5\n\n",
                style="cyan",
            )

            body.append("Remediation / Next Steps:\n", style="bold")
            body.append(f"  {finding.remediation}\n", style="green")

            console.print(Panel(body, title=f_title, border_style="dim", expand=False))

    # 4. Policy Gate Status
    policy = result.policy_evaluation
    if policy.blocked:
        gate_text = Text()
        gate_text.append("DEPLOYMENT BLOCKED BY POLICY\n", style="bold red")
        for reason in policy.blocking_reasons:
            gate_text.append(f"- {reason}\n", style="red")
        console.print(Panel(gate_text, border_style="red", expand=False))
    else:
        status_msg = "PASSED: No configured policy conditions were violated."
        console.print(
            Panel(Text(status_msg, style="bold green"), border_style="green", expand=False)
        )


def render_json_report(result: AnalysisResult) -> str:
    """Render a deterministic, redacted JSON report."""
    return json.dumps(result.to_dict(), indent=2, sort_keys=False)


def render_markdown_report(result: AnalysisResult) -> str:
    """Render a sanitized Markdown report suitable for GitHub PR comments and CI summaries."""
    lines: list[str] = []

    # Title & Badge
    lines.append("# Preflight Infrastructure Risk Report\n")

    policy = result.policy_evaluation
    if policy.blocked:
        lines.append("> 🛑 **Deployment Blocked by Preflight Policy**\n")
        for reason in policy.blocking_reasons:
            lines.append(f"> - {reason}")
        lines.append("")
    else:
        lines.append(
            "> ✅ **Preflight Passed** — No configured blocking policies were triggered.\n"
        )

    # Overview table
    lines.append("## Overview\n")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| **Plan Path** | `{result.plan_path}` |")
    lines.append(f"| **Environment** | `{result.environment.value.upper()}` |")
    lines.append(f"| **Overall Risk Score** | **{result.overall_risk_score:.1f} / 100** |")
    lines.append(f"| **Risk Category** | `{result.overall_risk_category.value.upper()}` |")
    if result.highest_contributing_resource:
        lines.append(f"| **Highest Risk Resource** | `{result.highest_contributing_resource}` |")
    lines.append(f"| **Total Findings** | {len(result.findings)} |")
    lines.append("")

    # Operations breakdown
    summary = result.summary
    lines.append("### Planned Operations\n")
    lines.append("| Create | Update | Delete | Replace | Read / No-op | Unknown Actions |")
    lines.append("|:---:|:---:|:---:|:---:|:---:|:---:|")
    lines.append(
        f"| {summary.to_create} | {summary.to_update} | {summary.to_delete} | "
        f"{summary.to_replace} | {summary.to_read} / {summary.to_noop} | {summary.unknown_actions} |"
    )
    lines.append("")

    # Findings
    if not result.findings:
        lines.append("## Findings\n")
        lines.append("No risk findings detected for this Terraform plan.\n")
    else:
        lines.append(f"## Risk Findings ({len(result.findings)})\n")
        for idx, finding in enumerate(result.findings, start=1):
            sev_badge = f"**{finding.severity.value.upper()}**"
            lines.append(f"### {idx}. [{finding.rule_id}] {finding.rule_name} — {sev_badge}\n")
            lines.append(
                f"- **Resource:** `{finding.resource_address}` (`{finding.resource_type}`)"
            )
            lines.append(f"- **Action:** `{finding.action.value.upper()}`")
            lines.append(f"- **Risk Score:** `{finding.calculated_score:.1f}`")
            lines.append(f"- **What Changed:** {finding.what_changed}")
            lines.append(f"- **Why It Matters:** {finding.why_it_matters}")

            rf = finding.risk_factors
            lines.append(
                f"- **Risk Factors:** Impact: `{rf.change_impact:.1f}/5` | "
                f"Security: `{rf.security_exposure:.1f}/5` | "
                f"Reversibility: `{rf.reversibility:.1f}/5` | "
                f"Env: `{rf.environment_criticality:.1f}/5` | "
                f"Uncertainty: `{rf.uncertainty:.1f}/5`"
            )
            lines.append(f"- **Remediation:** {finding.remediation}\n")

    lines.append("---")
    lines.append(
        "*Generated by [Preflight](https://github.com/preflight-engine/preflight) — Infrastructure Change Risk Analysis Engine.*"
    )

    return "\n".join(lines)


def get_terminal_report_str(result: AnalysisResult) -> str:
    """Helper to get the terminal report as a plain string (useful for testing or writing to file)."""
    buf = StringIO()
    render_terminal_report(result, file=buf)
    return buf.getvalue()
