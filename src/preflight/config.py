"""Configuration management for Preflight."""

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from preflight.models import Environment, Severity

DEFAULT_CONFIG_FILENAMES = [
    "preflight.yaml",
    "preflight.yml",
    ".preflight.yaml",
    ".preflight.yml",
]


class ConfigError(Exception):
    """Raised when configuration cannot be loaded or is invalid."""


class PreflightConfig(BaseModel):
    environment: str = Field(default="production", description="Target environment context")
    fail_on: str | None = Field(default=None, description="Minimum severity to block deployment")
    blocked_rules: list[str] = Field(
        default_factory=list, description="Rules that unconditionally block"
    )
    allowed_rules: list[str] = Field(
        default_factory=list, description="Rules to ignore or suppress"
    )
    max_score: float | None = Field(default=None, description="Maximum allowed plan risk score")
    format: str = Field(default="terminal", description="Output report format")
    verbose: bool = Field(default=False, description="Enable detailed output")

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        try:
            Environment.from_str(v)
            return v.lower()
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("fail_on")
    @classmethod
    def validate_fail_on(cls, v: str | None) -> str | None:
        if v is None:
            return None
        try:
            Severity.from_str(v)
            return v.lower()
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized not in ("terminal", "json", "markdown"):
            raise ValueError(f"Invalid format '{v}'. Valid options: terminal, json, markdown.")
        return normalized

    @field_validator("max_score")
    @classmethod
    def validate_max_score(cls, v: float | None) -> float | None:
        if v is not None and (v < 0.0 or v > 100.0):
            raise ValueError("max_score must be between 0.0 and 100.0.")
        return v


def load_config(config_path: str | Path | None = None) -> PreflightConfig:
    """Load and validate configuration from a file or discover the default."""
    target_path: Path | None = None

    if config_path is not None:
        target_path = Path(config_path)
        if not target_path.exists():
            raise ConfigError(f"Config file not found: '{target_path}'.")
    else:
        for filename in DEFAULT_CONFIG_FILENAMES:
            candidate = Path(filename)
            if candidate.exists() and candidate.is_file():
                target_path = candidate
                break

    if target_path is None:
        return PreflightConfig()

    try:
        content = target_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Failed to read config file '{target_path}': {exc}") from exc

    try:
        raw_data = yaml.safe_load(content) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML syntax in '{target_path}': {exc}") from exc

    if not isinstance(raw_data, dict):
        raise ConfigError(f"Configuration in '{target_path}' must be a key-value mapping.")

    try:
        return PreflightConfig(**raw_data)
    except Exception as exc:
        raise ConfigError(f"Configuration validation error in '{target_path}': {exc}") from exc
