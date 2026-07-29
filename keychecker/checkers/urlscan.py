"""urlscan.io API key checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class UrlscanChecker(BaseChecker):
    name = "urlscan"
    display_name = "urlscan.io"
    fields = ("key",)
    env_vars = {"key": "URLSCAN_API_KEY"}
    help = "urlscan.io API key"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        key = self.credentials["key"]
        headers = {"API-Key": key}
        try:
            resp = await client.get(
                "https://urlscan.io/user/quotas/", headers=headers
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json()
            limits = data.get("limits", {})
            public = limits.get("public", {})
            detail = (
                f"public_day={public.get('day', {}).get('remaining', '?')} "
                f"desc={data.get('description', '?')}"
            )
            return self.valid(detail, **data)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
