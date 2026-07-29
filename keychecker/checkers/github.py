"""GitHub personal access token checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class GitHubChecker(BaseChecker):
    name = "github"
    display_name = "GitHub"
    fields = ("token",)
    env_vars = {"token": "GITHUB_TOKEN"}
    help = "GitHub personal access token"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        token = self.credentials["token"]
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        try:
            resp = await client.get("https://api.github.com/user", headers=headers)
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json()
            # Classic PATs expose their scopes here; fine-grained tokens don't.
            scopes = resp.headers.get("X-OAuth-Scopes", "").strip()
            scope_str = scopes if scopes else "fine-grained/none"
            limit = resp.headers.get("X-RateLimit-Limit", "?")
            remaining = resp.headers.get("X-RateLimit-Remaining", "?")
            detail = (
                f"login={data.get('login', '?')} "
                f"scopes=[{scope_str}] "
                f"rate={remaining}/{limit}"
            )
            return self.valid(
                detail,
                login=data.get("login"),
                scopes=scopes,
                rate_limit=limit,
                rate_remaining=remaining,
            )
        if resp.status_code == 401:
            return self.invalid("unauthorized (HTTP 401)")
        if resp.status_code == 403:
            return self.invalid("forbidden (HTTP 403) — token valid but access denied")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
