"""Intelligence X (intelx) API key checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class IntelXChecker(BaseChecker):
    name = "intelx"
    display_name = "Intelligence X"
    fields = ("key",)
    env_vars = {"key": "INTELX_API_KEY"}
    help = "Intelligence X API key"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        key = self.credentials["key"]
        headers = {"x-key": key}
        try:
            resp = await client.get(
                "https://2.intelx.io/authenticate/info", headers=headers
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json()
            detail = (
                f"tier={data.get('tier', '?')} "
                f"paths={data.get('paths', '?')} "
                f"expires={data.get('added', '?')}"
            )
            return self.valid(detail, **data)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
