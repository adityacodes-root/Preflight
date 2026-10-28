"""Command Line Interface for Preflight."""

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

# Ensure UTF-8 output on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from preflight import __version__
from preflight.config import ConfigError, load_config
from preflight.engine import PreflightEngine
from preflight.github import GitHubApiError, post_or_update_pr_comment, resolve_github_context
from preflight.models import Environment, Severity
from preflight.plan import PlanParseError
from preflight.policy import PolicyEvaluator
from preflight.reporting import (
    render_json_report,
    render_markdown_report,
    render_pr_comment,
    render_sarif_report,
    render_terminal_report,
)

err_console = Console(stderr=True)

MAIN_HELP = """\
[bold]Preflight[/bold]: Infrastructure Change Risk Analysis Engine for Terraform plans.

Analyzes Terraform execution plans to detect destructive operations, security
regressions, and architectural risks before changes reach production.
"""

MAIN_EPILOG = """\
[bold green]Terraform Integration Workflow:[/bold green]

  [bold cyan]Workflow A: Direct Stdin Stream (Zero disk artifacts - Recommended for CI/CD)[/bold cyan]
    $ terraform plan -out=tfplan
    $ terraform show -json tfplan | preflight analyze - --fail-on high

  [bold cyan]Workflow B: Local Plan File Analysis[/bold cyan]
    $ terraform plan -out=tfplan
    $ terraform show -json tfplan > plan.json
    $ preflight analyze plan.json --environment production

  [bold cyan]Workflow C: GitHub Pull Request Sticky Comment Gate[/bold cyan]
    $ terraform show -json tfplan | preflight comment - --fail-on high

  [bold cyan]Workflow D: GitHub Code Scanning & SARIF Upload[/bold cyan]
    $ terraform show -json tfplan | preflight analyze - --format sarif --output preflight.sarif

[bold green]Supported Cloud Providers & Detection Rules:[/bold green]

  [bold cyan]AWS (AWS-*)[/bold cyan]
    • AWS-NET-001: Security group ingress allowing SSH (22), RDP (3389), or all traffic to 0.0.0.0/0
    • AWS-S3-001:  S3 Public Access Block removal or disabled settings; public bucket ACLs
    • AWS-IAM-001: Permissive IAM wildcard policies (* on * is Critical; service-level wildcards is High)
    • AWS-DB-001:  Deletion or replacement of RDS instances, Aurora clusters, DynamoDB, or ElastiCache

  [bold cyan]Azure (AZR-*)[/bold cyan]
    • AZR-NET-001: Network Security Group (NSG) rules allowing Internet to ports 22, 3389, or wildcard *
    • AZR-STG-001: Storage account public blob access or missing firewall restrictions
    • AZR-KV-001:  Azure Key Vault changes with purge protection disabled or soft delete retention < 7 days
    • AZR-DB-001:  Deletion or replacement of Azure SQL, Cosmos DB, or PostgreSQL flexible servers

  [bold cyan]Google Cloud (GCP-*)[/bold cyan]
    • GCP-FW-001:  Ingress compute firewall rules allowing 0.0.0.0/0 to ports 22, 3389, or all protocols
    • GCP-IAM-001: Cloud Storage bucket IAM bindings granting access to allUsers or allAuthenticatedUsers
    • GCP-SQL-001: Cloud SQL instance deletion, replacement, or disabling deletion_protection

  [bold cyan]Kubernetes & Helm (K8S-*)[/bold cyan]
    • K8S-SEC-001: Workloads deploying with container privileged: true or hostNetwork/hostPID/hostIPC
    • K8S-RBAC-001: RoleBindings and ClusterRoleBindings binding to superuser role cluster-admin

  [bold cyan]Generic (GEN-*)[/bold cyan]
    • GEN-DEL-001: Permanent resource deletion in Terraform plan
    • GEN-REP-001: Resource replacement (destroy and recreate due to immutable attribute changes)
    • GEN-DST-001: Destructive changes targeting stateful infrastructure (databases, volumes, clusters)
    • GEN-UNK-001: Computed unknown values present in critical configuration fields
    • GEN-ACT-001: Unrecognized or unsupported Terraform lifecycle action sequences

[bold green]CI/CD Gate Exit Codes:[/bold green]

  [bold]0 (Pass)[/bold]   Analysis completed successfully. No configured policy conditions were violated.
  [bold]1 (Block)[/bold]  Deployment blocked. A configured policy threshold (--fail-on) or blocked rule triggered.
  [bold]2 (Error)[/bold]  Execution error. Plan file not found, invalid JSON syntax, or bad configuration.

[bold green]Documentation & Repository:[/bold green]
  https://github.com/adityacodes-root/Preflight
"""

ANALYZE_EPILOG = """\
[bold green]Terraform Usage Examples & Patterns:[/bold green]

  [bold cyan]1. Stream directly via pipe (recommended in CI/CD pipelines):[/bold cyan]
    $ terraform show -json tfplan | preflight analyze -

  [bold cyan]2. Block CI/CD pipeline on High or Critical severity findings:[/bold cyan]
    $ terraform show -json tfplan | preflight analyze - --fail-on high

  [bold cyan]3. Set environment criticality (development, staging, production):[/bold cyan]
    $ preflight analyze plan.json --environment production

  [bold cyan]4. Export as SARIF v2.1.0 for GitHub Code Scanning / Security Tab:[/bold cyan]
    $ terraform show -json tfplan | preflight analyze - --format sarif --output preflight.sarif

  [bold cyan]5. Export JSON report for downstream scripts or Slack / webhook bots:[/bold cyan]
    $ preflight analyze plan.json --format json --output report.json

  [bold cyan]6. Export Markdown report for pull requests or documentation:[/bold cyan]
    $ preflight analyze plan.json --format markdown --output report.md

  [bold cyan]7. Load custom organization policy file (preflight.yaml):[/bold cyan]
    $ preflight analyze plan.json --config .preflight.yaml

[bold green]Exit Codes:[/bold green]
  0 = Pass (Changes safe or below threshold)
  1 = Block (Severity threshold met or blocked rule violated)
  2 = Error (Invalid JSON, bad arguments, or file read error)
"""

COMMENT_EPILOG = """\
[bold green]GitHub Actions CI/CD Usage:[/bold green]

  [bold cyan]1. Automatic Context Resolution (Standard GitHub Actions workflow):[/bold cyan]
    In CI, GITHUB_REPOSITORY, GITHUB_TOKEN, and PR numbers (from GITHUB_REF)
    are detected automatically. Subsequent runs update the comment in place:

    - name: Preflight PR Risk Gate
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      run: |
        terraform show -json tfplan | preflight comment - --fail-on high

  [bold cyan]2. Local Dry-Run (preview markdown without calling GitHub API):[/bold cyan]
    $ preflight comment plan.json --dry-run --fail-on high

  [bold cyan]3. Explicit Parameters (Custom runners, external PRs, or testing):[/bold cyan]
    $ preflight comment plan.json --repo owner/repo --pr 42 --token $GITHUB_TOKEN
"""

app = typer.Typer(
    name="preflight",
    help=MAIN_HELP,
    epilog=MAIN_EPILOG,
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"preflight {__version__}")
        raise typer.Exit(code=0)


@app.callback()
def main_callback(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            help="Show the Preflight version and exit.",
        ),
    ] = False,
) -> None:
    pass


@app.command(
    name="analyze",
    help="Analyze a Terraform plan JSON file or stdin stream for infrastructure risk.",
    epilog=ANALYZE_EPILOG,
)
def analyze(
    plan_path: Annotated[
        str,
        typer.Argument(
            help="Path to Terraform plan JSON file or '-' to read from stdin pipe.",
            show_default=False,
        ),
    ],
    environment: Annotated[
        str | None,
        typer.Option(
            "--environment",
            "-e",
            help="Target environment (development, staging, production).",
        ),
    ] = None,
    format_type: Annotated[
        str | None,
        typer.Option(
            "--format",
            "-f",
            help="Output format: terminal, json, markdown, or sarif.",
        ),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Block deployment if findings meet or exceed this severity (low, moderate, high, critical).",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="File path to save the generated report.",
        ),
    ] = None,
    config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to preflight configuration file (YAML).",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose output.",
        ),
    ] = False,
) -> None:
    """Analyze a Terraform plan JSON file and assess deployment risk."""
    # 1. Load configuration
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        err_console.print(f"[bold red]Configuration Error:[/bold red] {exc}")
        sys.exit(2)

    # 2. Merge CLI overrides with config file values
    effective_env_str = environment or config.environment
    try:
        effective_env = Environment.from_str(effective_env_str)
    except ValueError as exc:
        err_console.print(f"[bold red]Environment Error:[/bold red] {exc}")
        sys.exit(2)

    effective_format = (format_type or config.format).strip().lower()
    if effective_format not in ("terminal", "json", "markdown", "sarif"):
        err_console.print(
            f"[bold red]Invalid Format:[/bold red] '{effective_format}'. Valid options: terminal, json, markdown, sarif."
        )
        sys.exit(2)

    effective_fail_on_str = fail_on or config.fail_on
    effective_fail_on: Severity | None = None
    if effective_fail_on_str:
        try:
            effective_fail_on = Severity.from_str(effective_fail_on_str)
        except ValueError as exc:
            err_console.print(f"[bold red]Policy Error:[/bold red] {exc}")
            sys.exit(2)

    # 3. Configure policy evaluator
    policy_evaluator = PolicyEvaluator(
        fail_on_severity=effective_fail_on,
        blocked_rules=config.blocked_rules,
        allowed_rules=config.allowed_rules,
        max_allowed_score=config.max_score,
    )

    # 4. Run Analysis
    engine = PreflightEngine()
    try:
        result = engine.analyze_file(
            plan_path=plan_path,
            environment=effective_env,
            policy_evaluator=policy_evaluator,
        )
    except PlanParseError as exc:
        err_console.print(f"[bold red]Plan Parse Error:[/bold red] {exc}")
        sys.exit(2)
    except Exception as exc:
        err_console.print(f"[bold red]Execution Error:[/bold red] {exc}")
        if verbose:
            err_console.print_exception()
        sys.exit(2)

    # 5. Render Output
    if effective_format == "json":
        json_output = render_json_report(result)
        if output:
            try:
                output.write_text(json_output, encoding="utf-8")
            except OSError as exc:
                err_console.print(
                    f"[bold red]Output Error:[/bold red] Failed to write to '{output}': {exc}"
                )
                sys.exit(2)
        else:
            typer.echo(json_output)

    elif effective_format == "markdown":
        md_output = render_markdown_report(result)
        if output:
            try:
                output.write_text(md_output, encoding="utf-8")
            except OSError as exc:
                err_console.print(
                    f"[bold red]Output Error:[/bold red] Failed to write to '{output}': {exc}"
                )
                sys.exit(2)
        else:
            typer.echo(md_output)

    elif effective_format == "sarif":
        sarif_output = render_sarif_report(result)
        if output:
            try:
                output.write_text(sarif_output, encoding="utf-8")
            except OSError as exc:
                err_console.print(
                    f"[bold red]Output Error:[/bold red] Failed to write to '{output}': {exc}"
                )
                sys.exit(2)
        else:
            typer.echo(sarif_output)

    else:  # terminal
        if output:
            try:
                with output.open("w", encoding="utf-8") as f:
                    render_terminal_report(result, file=f)
            except OSError as exc:
                err_console.print(
                    f"[bold red]Output Error:[/bold red] Failed to write to '{output}': {exc}"
                )
                sys.exit(2)
        else:
            render_terminal_report(result)

    # 6. Exit code
    if result.policy_evaluation.blocked:
        sys.exit(1)
    sys.exit(0)


@app.command(
    name="comment",
    help="Analyze a plan and publish or update a sticky GitHub Pull Request comment.",
    epilog=COMMENT_EPILOG,
)
def comment(
    plan_path: Annotated[
        str,
        typer.Argument(
            help="Path to Terraform plan JSON file or '-' to read from stdin pipe.",
            show_default=False,
        ),
    ],
    pr: Annotated[
        int | None,
        typer.Option(
            "--pr",
            "-p",
            help="Pull request number (defaults to PR_NUMBER or GITHUB_REF in CI).",
        ),
    ] = None,
    repo: Annotated[
        str | None,
        typer.Option(
            "--repo",
            "-R",
            help="Target repository 'owner/repo' (defaults to GITHUB_REPOSITORY).",
        ),
    ] = None,
    token: Annotated[
        str | None,
        typer.Option(
            "--token",
            "-t",
            help="GitHub API token (defaults to GITHUB_TOKEN or GH_TOKEN).",
        ),
    ] = None,
    environment: Annotated[
        str | None,
        typer.Option(
            "--environment",
            "-e",
            help="Target environment (development, staging, production).",
        ),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Block deployment if findings meet or exceed this severity.",
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Render the comment markdown without calling the GitHub API.",
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Save the rendered comment markdown to a file.",
        ),
    ] = None,
    config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to preflight configuration file (YAML).",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose output.",
        ),
    ] = False,
) -> None:
    """Analyze a plan and publish or update a sticky GitHub Pull Request comment."""
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        err_console.print(f"[bold red]Configuration Error:[/bold red] {exc}")
        sys.exit(2)

    effective_env_str = environment or config.environment
    try:
        effective_env = Environment.from_str(effective_env_str)
    except ValueError as exc:
        err_console.print(f"[bold red]Environment Error:[/bold red] {exc}")
        sys.exit(2)

    effective_fail_on_str = fail_on or config.fail_on
    effective_fail_on: Severity | None = None
    if effective_fail_on_str:
        try:
            effective_fail_on = Severity.from_str(effective_fail_on_str)
        except ValueError as exc:
            err_console.print(f"[bold red]Policy Error:[/bold red] {exc}")
            sys.exit(2)

    policy_evaluator = PolicyEvaluator(
        fail_on_severity=effective_fail_on,
        blocked_rules=config.blocked_rules,
        allowed_rules=config.allowed_rules,
        max_allowed_score=config.max_score,
    )

    engine = PreflightEngine()
    try:
        result = engine.analyze_file(
            plan_path=plan_path,
            environment=effective_env,
            policy_evaluator=policy_evaluator,
        )
    except PlanParseError as exc:
        err_console.print(f"[bold red]Plan Parse Error:[/bold red] {exc}")
        sys.exit(2)
    except Exception as exc:
        err_console.print(f"[bold red]Execution Error:[/bold red] {exc}")
        if verbose:
            err_console.print_exception()
        sys.exit(2)

    comment_body = render_pr_comment(result)

    if output:
        try:
            output.write_text(comment_body, encoding="utf-8")
        except OSError as exc:
            err_console.print(
                f"[bold red]Output Error:[/bold red] Failed to write to '{output}': {exc}"
            )
            sys.exit(2)

    if dry_run:
        typer.echo(comment_body)
    else:
        try:
            resolved_repo, resolved_pr, resolved_token = resolve_github_context(
                repo=repo, pr=pr, token=token
            )
            resp = post_or_update_pr_comment(
                repo=resolved_repo,
                pr_number=resolved_pr,
                token=resolved_token,
                comment_body=comment_body,
            )
            action = resp.get("action", "posted")
            url = resp.get("url", "")
            err_console.print(
                f"[bold green]PR Comment {action.capitalize()}:[/bold green] {resolved_repo}#{resolved_pr} {url}".strip()
            )
        except GitHubApiError as exc:
            err_console.print(f"[bold red]GitHub Comment Error:[/bold red] {exc}")
            sys.exit(2)

    if result.policy_evaluation.blocked:
        sys.exit(1)
    sys.exit(0)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
