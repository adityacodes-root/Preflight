"""Tests for GitHub PR comment posting and sticky update logic."""

import json
from io import BytesIO
from typing import Any
from urllib.error import HTTPError

import pytest

from preflight.github import (
    GitHubApiError,
    parse_pr_number_from_ref,
    post_or_update_pr_comment,
    resolve_github_context,
)
from preflight.reporting import PR_COMMENT_MARKER


def test_parse_pr_number_from_ref() -> None:
    assert parse_pr_number_from_ref("refs/pull/42/merge") == 42
    assert parse_pr_number_from_ref("refs/pull/105/head") == 105
    assert parse_pr_number_from_ref("pull/99/head") == 99
    assert parse_pr_number_from_ref("55") == 55
    assert parse_pr_number_from_ref("refs/heads/main") is None


def test_resolve_github_context_explicit() -> None:
    repo, pr, token = resolve_github_context("owner/repo", 123, "ghp_secret")
    assert repo == "owner/repo"
    assert pr == 123
    assert token == "ghp_secret"


def test_resolve_github_context_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "my-org/infra")
    monkeypatch.setenv("PR_NUMBER", "456")
    monkeypatch.setenv("GITHUB_TOKEN", "token_from_env")

    repo, pr, token = resolve_github_context()
    assert repo == "my-org/infra"
    assert pr == 456
    assert token == "token_from_env"


def test_resolve_github_context_from_github_ref(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "my-org/infra")
    monkeypatch.delenv("PR_NUMBER", raising=False)
    monkeypatch.setenv("GITHUB_REF", "refs/pull/789/merge")
    monkeypatch.setenv("GH_TOKEN", "fallback_token")

    repo, pr, token = resolve_github_context()
    assert repo == "my-org/infra"
    assert pr == 789
    assert token == "fallback_token"


def test_resolve_github_context_missing_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("PR_NUMBER", raising=False)
    monkeypatch.delenv("GITHUB_REF", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    with pytest.raises(GitHubApiError, match="GitHub repository not specified"):
        resolve_github_context(None, 1, "token")

    with pytest.raises(GitHubApiError, match="Pull request number not specified"):
        resolve_github_context("owner/repo", None, "token")

    with pytest.raises(GitHubApiError, match="GitHub token not found"):
        resolve_github_context("owner/repo", 1, None)


class MockResponse:
    def __init__(self, status: int = 200, body_dict: Any = None) -> None:
        self.status = status
        self.code = status
        self._content = json.dumps(body_dict or {}).encode("utf-8")

    def read(self) -> bytes:
        return self._content

    def __enter__(self) -> "MockResponse":
        return self

    def __exit__(self, *args: Any) -> None:
        pass


def _mock_http_response(status: int = 200, body_dict: Any = None) -> MockResponse:
    return MockResponse(status=status, body_dict=body_dict)


def test_post_or_update_pr_comment_creates_new(monkeypatch: pytest.MonkeyPatch) -> None:
    call_log: list[tuple[str, str]] = []

    def mock_urlopen(req: Any) -> Any:
        call_log.append((req.get_method(), req.full_url))
        if req.get_method() == "GET":
            # Return list of comments without marker
            return _mock_http_response(200, [{"id": 1, "body": "regular user comment"}])
        if req.get_method() == "POST":
            return _mock_http_response(
                201, {"id": 100, "html_url": "https://github.com/comment/100"}
            )
        return _mock_http_response(200, {})

    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

    result = post_or_update_pr_comment(
        repo="owner/repo",
        pr_number=10,
        token="test_token",
        comment_body=f"{PR_COMMENT_MARKER}\n# Report",
    )

    assert result["action"] == "created"
    assert result["comment_id"] == 100
    assert len(call_log) == 2
    assert call_log[0][0] == "GET"
    assert call_log[1][0] == "POST"


def test_post_or_update_pr_comment_updates_existing(monkeypatch: pytest.MonkeyPatch) -> None:
    call_log: list[tuple[str, str]] = []

    def mock_urlopen(req: Any) -> Any:
        call_log.append((req.get_method(), req.full_url))
        if req.get_method() == "GET":
            return _mock_http_response(
                200,
                [
                    {"id": 1, "body": "first comment"},
                    {"id": 999, "body": f"Older report {PR_COMMENT_MARKER}"},
                ],
            )
        if req.get_method() == "PATCH":
            return _mock_http_response(
                200, {"id": 999, "html_url": "https://github.com/comment/999"}
            )
        return _mock_http_response(200, {})

    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

    result = post_or_update_pr_comment(
        repo="owner/repo",
        pr_number=10,
        token="test_token",
        comment_body=f"{PR_COMMENT_MARKER}\n# Updated Report",
    )

    assert result["action"] == "updated"
    assert result["comment_id"] == 999
    assert len(call_log) == 2
    assert call_log[0][0] == "GET"
    assert call_log[1][0] == "PATCH"


def test_post_or_update_pr_comment_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def mock_urlopen(req: Any) -> Any:
        fp = BytesIO(b'{"message": "Resource not accessible by integration"}')
        raise HTTPError(req.full_url, 403, "Forbidden", hdrs={}, fp=fp)  # type: ignore

    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

    with pytest.raises(GitHubApiError, match="GitHub API error"):
        post_or_update_pr_comment(
            repo="owner/repo",
            pr_number=10,
            token="test_token",
            comment_body="test",
        )
