"""ZoomEye API key checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class ZoomEyeChecker(BaseChecker):
    name = "zoomeye"
    display_name = "ZoomEye"
    fields = ("key",)
    env_vars = {"key": "ZOOMEYE_API_KEY"}
    help = "ZoomEye API key"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        key = self.credentials["key"]
        headers = {"API-KEY": key}
        try:
            resp = await client.get(
                "https://api.zoomeye.org/resources-info", headers=headers
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json()
            plan = data.get("plan", "?")
            quota = data.get("quota_info", {})
            detail = (
                f"plan={plan} "
                f"search_remain={quota.get('remain_total_quota', '?')}"
            )
            return self.valid(detail, **data)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
