"""Input layer: Read, validate, and normalize Terraform plan JSON."""

import json
import sys
from pathlib import Path

from preflight.models import ActionType, PlanSummary, ResourceChange


class PlanParseError(Exception):
    """Raised when a Terraform plan file cannot be read or parsed."""


def parse_plan_file(plan_path: str | Path) -> tuple[list[ResourceChange], PlanSummary]:
    """Read and validate a Terraform plan JSON file or stdin stream."""
    path_str = str(plan_path)
    if path_str == "-":
        try:
            content = sys.stdin.read()
        except OSError as exc:
            raise PlanParseError(f"Failed to read from standard input: {exc}") from exc
        if not content.strip():
            raise PlanParseError("Standard input is empty.")
        return parse_plan_json(content)

    path = Path(plan_path)
    if not path.exists():
        raise PlanParseError(f"Plan file not found: '{path}'. Ensure the path is correct.")
    if path.is_dir():
        raise PlanParseError(f"Plan path '{path}' is a directory, not a file.")

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise PlanParseError(f"File '{path}' is not valid UTF-8 text: {exc}") from exc
    except OSError as exc:
        raise PlanParseError(f"Failed to read file '{path}': {exc}") from exc

    return parse_plan_json(content)


def parse_plan_json(json_content: str) -> tuple[list[ResourceChange], PlanSummary]:
    """Parse raw JSON string representation of a Terraform plan."""
    if not json_content.strip():
        raise PlanParseError("Plan file is empty.")

    try:
        data = json.loads(json_content)
    except json.JSONDecodeError as exc:
        raise PlanParseError(
            f"Invalid JSON syntax at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc

    if not isinstance(data, dict):
        raise PlanParseError(
            f"Unsupported plan format: expected JSON object at root, got {type(data).__name__}."
        )

    # Validate Terraform plan signature (must have format_version or resource_changes or planned_values)
    is_tf_plan = any(
        k in data
        for k in ("format_version", "terraform_version", "resource_changes", "planned_values")
    )
    if not is_tf_plan:
        raise PlanParseError(
            "JSON structure does not appear to be a Terraform plan. "
            "Ensure you generated it via 'terraform show -json <tfplan>'."
        )

    raw_changes = data.get("resource_changes", [])
    if not isinstance(raw_changes, list):
        raise PlanParseError(
            f"'resource_changes' must be an array, got {type(raw_changes).__name__}."
        )

    resource_changes: list[ResourceChange] = []
    summary = PlanSummary(total_resources=len(raw_changes))

    for idx, item in enumerate(raw_changes):
        if not isinstance(item, dict):
            raise PlanParseError(f"resource_changes[{idx}] is not an object.")

        address = str(item.get("address", f"resource_{idx}"))
        mode = str(item.get("mode", "managed"))
        res_type = str(item.get("type", "unknown"))
        name = str(item.get("name", "unknown"))
        provider_name = str(item.get("provider_name", "unknown"))
        module_address = item.get("module_address")

        change = item.get("change")
        if not isinstance(change, dict):
            actions = ["unknown"]
            before = None
            after = None
            after_unknown = None
            replace_paths = None
            before_sensitive = None
            after_sensitive = None
        else:
            raw_actions = change.get("actions", [])
            actions = (
                [str(a) for a in raw_actions] if isinstance(raw_actions, list) else ["unknown"]
            )
            before = change.get("before") if isinstance(change.get("before"), dict) else None
            after = change.get("after") if isinstance(change.get("after"), dict) else None
            after_unknown = (
                change.get("after_unknown")
                if isinstance(change.get("after_unknown"), dict)
                else None
            )
            replace_paths = (
                change.get("replace_paths")
                if isinstance(change.get("replace_paths"), list)
                else None
            )
            before_sensitive = change.get("before_sensitive")
            after_sensitive = change.get("after_sensitive")

        action_type = ActionType.from_terraform_actions(actions)

        # Update summary counts
        match action_type:
            case ActionType.CREATE:
                summary.to_create += 1
            case ActionType.UPDATE:
                summary.to_update += 1
            case ActionType.DELETE:
                summary.to_delete += 1
            case ActionType.REPLACE:
                summary.to_replace += 1
            case ActionType.READ:
                summary.to_read += 1
            case ActionType.NOOP:
                summary.to_noop += 1
            case ActionType.UNKNOWN:
                summary.unknown_actions += 1

        if after_unknown and any(v for v in after_unknown.values()):
            summary.has_unknown_values = True

        resource_changes.append(
            ResourceChange(
                address=address,
                module_address=str(module_address) if module_address else None,
                mode=mode,
                type=res_type,
                name=name,
                provider_name=provider_name,
                raw_actions=actions,
                action=action_type,
                before=before,
                after=after,
                after_unknown=after_unknown,
                replace_paths=replace_paths,
                before_sensitive=before_sensitive,
                after_sensitive=after_sensitive,
            )
        )

    return resource_changes, summary
