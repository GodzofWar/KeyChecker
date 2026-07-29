"""Shodan API key checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class ShodanChecker(BaseChecker):
    name = "shodan"
    display_name = "Shodan"
    fields = ("key",)
    env_vars = {"key": "SHODAN_API_KEY"}
    help = "Shodan API key"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        key = self.credentials["key"]
        try:
            resp = await client.get(
                "https://api.shodan.io/api-info", params={"key": key}
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json()
            plan = data.get("plan", "?")
            detail = (
                f"plan={plan} "
                f"query_credits={data.get('query_credits')} "
                f"scan_credits={data.get('scan_credits')}"
            )
            return self.valid(detail, **data)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
