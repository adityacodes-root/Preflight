"""GitHub PR comment integration using the GitHub REST API."""

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

from preflight import __version__
from preflight.reporting import PR_COMMENT_MARKER


class GitHubApiError(Exception):
    """Raised when GitHub API operations fail."""


def parse_pr_number_from_ref(ref: str) -> int | None:
    """Extract PR number from refs like 'refs/pull/123/merge' or '123/merge'."""
    match = re.search(r"pull/(\d+)/", ref)
    if match:
        return int(match.group(1))
    match = re.match(r"^(\d+)$", ref.strip())
    if match:
        return int(match.group(1))
    return None


def resolve_github_context(
    repo: str | None = None,
    pr: int | None = None,
    token: str | None = None,
) -> tuple[str, int, str]:
    """Resolve repository, pull request number, and token from options or environment."""
    resolved_repo = repo or os.environ.get("GITHUB_REPOSITORY")
    if not resolved_repo or "/" not in resolved_repo:
        raise GitHubApiError(
            "GitHub repository not specified. Pass '--repo owner/repo' or set GITHUB_REPOSITORY."
        )

    resolved_pr = pr
    if resolved_pr is None:
        pr_env = os.environ.get("PR_NUMBER")
        if pr_env and pr_env.isdigit():
            resolved_pr = int(pr_env)
        elif "GITHUB_REF" in os.environ:
            resolved_pr = parse_pr_number_from_ref(os.environ["GITHUB_REF"])

    if resolved_pr is None:
        raise GitHubApiError(
            "Pull request number not specified. Pass '--pr <number>' or set PR_NUMBER / GITHUB_REF in CI."
        )

    resolved_token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not resolved_token:
        raise GitHubApiError("GitHub token not found. Pass '--token <token>' or set GITHUB_TOKEN.")

    return resolved_repo, resolved_pr, resolved_token


def _github_request(
    url: str,
    token: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> Any:
    """Execute an authenticated HTTP request against GitHub's REST API."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": f"Preflight-Engine/{__version__}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            return json.loads(content) if content else {}
    except urllib.error.HTTPError as exc:
        err_msg = exc.read().decode("utf-8", errors="replace")
        raise GitHubApiError(f"GitHub API error ({exc.code} {exc.reason}): {err_msg}") from exc
    except urllib.error.URLError as exc:
        raise GitHubApiError(f"Network error connecting to GitHub API: {exc.reason}") from exc


def post_or_update_pr_comment(
    repo: str,
    pr_number: int,
    token: str,
    comment_body: str,
    marker: str = PR_COMMENT_MARKER,
) -> dict[str, Any]:
    """Publish a sticky PR comment, updating an existing comment if a marker is present."""
    comments_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"

    # 1. Search for existing sticky comment with our marker
    existing_comments = _github_request(f"{comments_url}?per_page=100", token, method="GET")
    existing_comment_id: int | None = None

    if isinstance(existing_comments, list):
        for comment in existing_comments:
            body = comment.get("body", "")
            if marker in body:
                existing_comment_id = int(comment["id"])
                break

    # 2. Update existing comment or create a new one
    if existing_comment_id is not None:
        patch_url = f"https://api.github.com/repos/{repo}/issues/comments/{existing_comment_id}"
        resp = _github_request(patch_url, token, method="PATCH", payload={"body": comment_body})
        return {
            "action": "updated",
            "comment_id": existing_comment_id,
            "url": resp.get("html_url", ""),
        }
    else:
        resp = _github_request(comments_url, token, method="POST", payload={"body": comment_body})
        return {
            "action": "created",
            "comment_id": resp.get("id"),
            "url": resp.get("html_url", ""),
        }
