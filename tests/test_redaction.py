"""Tests for defensive redaction of sensitive data."""

from pathlib import Path

from preflight.engine import PreflightEngine
from preflight.models import Environment
from preflight.redaction import (
    REDACTED_PLACEHOLDER,
    is_sensitive_key,
    redact_sensitive_data,
)
from preflight.reporting import render_json_report, render_markdown_report


def test_is_sensitive_key() -> None:
    assert is_sensitive_key("db_password") is True
    assert is_sensitive_key("api_secret_token") is True
    assert is_sensitive_key("client_secret") is True
    assert is_sensitive_key("private_key") is True
    assert is_sensitive_key("auth_bearer") is True
    assert is_sensitive_key("resource_name") is False
    assert is_sensitive_key("port") is False
    assert is_sensitive_key("allocated_storage") is False


def test_redact_sensitive_data_dictionary() -> None:
    data = {
        "engine": "postgres",
        "username": "admin",
        "master_password": "super-secret-12345",
        "nested": {
            "api_key": "secret-token",
            "normal_attr": "visible-value",
        },
    }
    redacted = redact_sensitive_data(data)

    assert redacted["engine"] == "postgres"
    assert redacted["username"] == "admin"
    assert redacted["master_password"] == REDACTED_PLACEHOLDER
    assert redacted["nested"]["api_key"] == REDACTED_PLACEHOLDER
    assert redacted["nested"]["normal_attr"] == "visible-value"


def test_redact_sensitive_marks() -> None:
    data = {
        "custom_field": "confidential_val",
        "public_field": "safe",
    }
    sensitive_marks = {
        "custom_field": True,
        "public_field": False,
    }
    redacted = redact_sensitive_data(data, sensitive_marks)
    assert redacted["custom_field"] == REDACTED_PLACEHOLDER
    assert redacted["public_field"] == "safe"


def test_full_plan_reports_do_not_leak_secrets() -> None:
    fixture_path = Path(__file__).parent / "fixtures" / "plans" / "sensitive-values.json"
    engine = PreflightEngine()
    result = engine.analyze_file(fixture_path, Environment.PRODUCTION)

    # 1. JSON report check
    json_str = render_json_report(result)
    assert "SUPER_SECRET_PLAINTEXT_PASSWORD_12345" not in json_str
    assert "ghp_SECRET_TOKEN_DO_NOT_LEAK" not in json_str
    assert "-----BEGIN RSA PRIVATE KEY-----" not in json_str

    # 2. Markdown report check
    md_str = render_markdown_report(result)
    assert "SUPER_SECRET_PLAINTEXT_PASSWORD_12345" not in md_str
    assert "ghp_SECRET_TOKEN_DO_NOT_LEAK" not in md_str
    assert "-----BEGIN RSA PRIVATE KEY-----" not in md_str
