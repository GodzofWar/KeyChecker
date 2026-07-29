"""BinaryEdge API key checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class BinaryEdgeChecker(BaseChecker):
    name = "binaryedge"
    display_name = "BinaryEdge"
    fields = ("key",)
    env_vars = {"key": "BINARYEDGE_API_KEY"}
    help = "BinaryEdge API key"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        key = self.credentials["key"]
        headers = {"X-Key": key}
        try:
            resp = await client.get(
                "https://api.binaryedge.io/v2/user/subscription", headers=headers
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json()
            sub = data.get("subscription", {})
            detail = (
                f"plan={sub.get('name', '?')} "
                f"requests_left={data.get('requests_left', '?')}/"
                f"{data.get('requests_plan', '?')}"
            )
            return self.valid(detail, **data)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
