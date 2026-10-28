"""Tests for Terraform plan parsing, action normalization, and error handling."""

from pathlib import Path

import pytest

from preflight.models import ActionType
from preflight.plan import PlanParseError, parse_plan_file, parse_plan_json


def test_parse_plan_json_valid_actions() -> None:
    sample_plan = """
    {
      "format_version": "1.2",
      "resource_changes": [
        {
          "address": "res.created",
          "type": "test_res",
          "name": "created",
          "change": { "actions": ["create"] }
        },
        {
          "address": "res.updated",
          "type": "test_res",
          "name": "updated",
          "change": { "actions": ["update"] }
        },
        {
          "address": "res.deleted",
          "type": "test_res",
          "name": "deleted",
          "change": { "actions": ["delete"] }
        },
        {
          "address": "res.replaced_dc",
          "type": "test_res",
          "name": "replaced_dc",
          "change": { "actions": ["delete", "create"] }
        },
        {
          "address": "res.replaced_cd",
          "type": "test_res",
          "name": "replaced_cd",
          "change": { "actions": ["create", "delete"] }
        },
        {
          "address": "res.read",
          "type": "test_res",
          "name": "read",
          "change": { "actions": ["read"] }
        },
        {
          "address": "res.noop",
          "type": "test_res",
          "name": "noop",
          "change": { "actions": ["no-op"] }
        },
        {
          "address": "res.unknown",
          "type": "test_res",
          "name": "unknown",
          "change": { "actions": ["taint_upgrade"] }
        }
      ]
    }
    """
    changes, summary = parse_plan_json(sample_plan)

    assert len(changes) == 8
    assert summary.total_resources == 8
    assert summary.to_create == 1
    assert summary.to_update == 1
    assert summary.to_delete == 1
    assert summary.to_replace == 2
    assert summary.to_read == 1
    assert summary.to_noop == 1
    assert summary.unknown_actions == 1

    actions_map = {c.address: c.action for c in changes}
    assert actions_map["res.created"] == ActionType.CREATE
    assert actions_map["res.updated"] == ActionType.UPDATE
    assert actions_map["res.deleted"] == ActionType.DELETE
    assert actions_map["res.replaced_dc"] == ActionType.REPLACE
    assert actions_map["res.replaced_cd"] == ActionType.REPLACE
    assert actions_map["res.read"] == ActionType.READ
    assert actions_map["res.noop"] == ActionType.NOOP
    assert actions_map["res.unknown"] == ActionType.UNKNOWN


def test_parse_plan_file_fixtures() -> None:
    fixtures_dir = Path(__file__).parent / "fixtures" / "plans"

    # Safe plan
    safe_path = Path(__file__).parent.parent / "examples" / "safe-plan.json"
    changes, summary = parse_plan_file(safe_path)
    assert summary.total_resources == 2
    assert summary.to_create == 1
    assert summary.to_read == 1

    # Replacement plan
    rep_path = fixtures_dir / "replacement-db.json"
    changes, summary = parse_plan_file(rep_path)
    assert summary.to_replace == 1

    # Empty plan
    empty_path = fixtures_dir / "empty-plan.json"
    changes, summary = parse_plan_file(empty_path)
    assert summary.total_resources == 0


def test_parse_plan_missing_file() -> None:
    with pytest.raises(PlanParseError, match="Plan file not found"):
        parse_plan_file("non_existent_file_path.json")


def test_parse_plan_empty_content() -> None:
    with pytest.raises(PlanParseError, match="Plan file is empty"):
        parse_plan_json("   ")


def test_parse_plan_malformed_json() -> None:
    fixtures_dir = Path(__file__).parent / "fixtures" / "plans"
    with pytest.raises(PlanParseError, match="Invalid JSON syntax"):
        parse_plan_file(fixtures_dir / "malformed.json")


def test_parse_plan_invalid_schema() -> None:
    fixtures_dir = Path(__file__).parent / "fixtures" / "plans"
    with pytest.raises(PlanParseError, match="does not appear to be a Terraform plan"):
        parse_plan_file(fixtures_dir / "invalid-schema.json")


def test_parse_plan_root_not_object() -> None:
    with pytest.raises(PlanParseError, match="expected JSON object at root"):
        parse_plan_json('["format_version", "1.2"]')


def test_parse_plan_resource_changes_not_array() -> None:
    with pytest.raises(PlanParseError, match="'resource_changes' must be an array"):
        parse_plan_json('{"format_version": "1.2", "resource_changes": "not_an_array"}')


def test_parse_plan_stdin_success(monkeypatch: pytest.MonkeyPatch) -> None:
    safe_path = Path(__file__).parent.parent / "examples" / "safe-plan.json"
    content = safe_path.read_text(encoding="utf-8")
    monkeypatch.setattr("sys.stdin", pytest.MonkeyPatch().context(), raising=False)
    from io import StringIO

    monkeypatch.setattr("sys.stdin", StringIO(content))
    changes, summary = parse_plan_file("-")
    assert summary.total_resources == 2
    assert len(changes) == 2


def test_parse_plan_stdin_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    from io import StringIO

    monkeypatch.setattr("sys.stdin", StringIO("   \n"))
    with pytest.raises(PlanParseError, match="Standard input is empty"):
        parse_plan_file("-")


def test_parse_plan_stdin_os_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class FailingStdin:
        def read(self) -> str:
            raise OSError("I/O failure")

    monkeypatch.setattr("sys.stdin", FailingStdin())
    with pytest.raises(PlanParseError, match="Failed to read from standard input"):
        parse_plan_file("-")


def test_parse_plan_stdin_interactive_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    class InteractiveStdin:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", InteractiveStdin())
    with pytest.raises(PlanParseError, match="Standard input is an interactive terminal"):
        parse_plan_file("-")
