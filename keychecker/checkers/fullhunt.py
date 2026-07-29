"""FullHunt API key checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class FullHuntChecker(BaseChecker):
    name = "fullhunt"
    display_name = "FullHunt"
    fields = ("key",)
    env_vars = {"key": "FULLHUNT_API_KEY"}
    help = "FullHunt API key"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        key = self.credentials["key"]
        headers = {"X-API-KEY": key}
        try:
            resp = await client.get(
                "https://fullhunt.io/api/v1/auth/status", headers=headers
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            user = resp.json().get("user", {})
            detail = (
                f"plan={user.get('plan', '?')} "
                f"remaining_credits={user.get('remaining_credits', '?')} "
                f"email={user.get('email', '?')}"
            )
            return self.valid(detail, **user)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
