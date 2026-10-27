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
from preflight.models import Environment, Severity
from preflight.plan import PlanParseError
from preflight.policy import PolicyEvaluator
from preflight.reporting import (
    render_json_report,
    render_markdown_report,
    render_terminal_report,
)

err_console = Console(stderr=True)

app = typer.Typer(
    name="preflight",
    help="Preflight: Infrastructure Change Risk Analysis Engine.",
    no_args_is_help=True,
    add_completion=False,
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
    help="Analyze a Terraform plan JSON file for infrastructure risk.",
)
def analyze(
    plan_path: Annotated[
        str,
        typer.Argument(
            help="Path to Terraform plan JSON file or '-' to read from stdin.",
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
            help="Output format: terminal, json, or markdown.",
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
    if effective_format not in ("terminal", "json", "markdown"):
        err_console.print(
            f"[bold red]Invalid Format:[/bold red] '{effective_format}'. Valid options: terminal, json, markdown."
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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
