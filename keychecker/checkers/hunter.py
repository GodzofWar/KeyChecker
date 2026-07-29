"""Hunter.io API key checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class HunterChecker(BaseChecker):
    name = "hunter"
    display_name = "Hunter.io"
    fields = ("key",)
    env_vars = {"key": "HUNTER_API_KEY"}
    help = "Hunter.io API key"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        key = self.credentials["key"]
        try:
            resp = await client.get(
                "https://api.hunter.io/v2/account", params={"api_key": key}
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json().get("data", {})
            requests = data.get("requests", {}).get("searches", {})
            detail = (
                f"plan={data.get('plan_name', '?')} "
                f"searches={requests.get('used', '?')}/{requests.get('available', '?')}"
            )
            return self.valid(detail, **data)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
