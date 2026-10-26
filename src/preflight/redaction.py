"""Defensive redaction of sensitive values from Terraform plans and findings."""

import re
from typing import Any

# Attribute name patterns that indicate sensitive or secret data
SENSITIVE_KEY_PATTERNS = re.compile(
    r"(password|secret|token|api_key|access_key|private_key|credential|auth|"
    r"cert|bearer|master_key|client_secret|ssh_key|encryption_key)",
    re.IGNORECASE,
)

REDACTED_PLACEHOLDER = "[REDACTED]"


def is_sensitive_key(key: str) -> bool:
    """Check if an attribute key matches sensitive naming patterns."""
    return bool(SENSITIVE_KEY_PATTERNS.search(key))


def redact_sensitive_data(
    data: Any,
    sensitive_marks: Any = None,
) -> Any:
    """Recursively redact sensitive values from a dictionary, list, or primitive.

    Respects both known sensitive key names and Terraform's sensitive_values metadata.
    """
    if sensitive_marks is True:
        return REDACTED_PLACEHOLDER

    if isinstance(data, dict):
        redacted_dict: dict[str, Any] = {}
        for key, value in data.items():
            child_marks = sensitive_marks.get(key) if isinstance(sensitive_marks, dict) else None

            if child_marks is True or is_sensitive_key(str(key)):
                redacted_dict[key] = REDACTED_PLACEHOLDER
            else:
                redacted_dict[key] = redact_sensitive_data(value, child_marks)
        return redacted_dict

    if isinstance(data, list):
        redacted_list: list[Any] = []
        for index, item in enumerate(data):
            child_marks = (
                sensitive_marks[index]
                if isinstance(sensitive_marks, list) and index < len(sensitive_marks)
                else None
            )
            redacted_list.append(redact_sensitive_data(item, child_marks))
        return redacted_list

    return data
