"""GreyNoise API key checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class GreyNoiseChecker(BaseChecker):
    name = "greynoise"
    display_name = "GreyNoise"
    fields = ("key",)
    env_vars = {"key": "GREYNOISE_API_KEY"}
    help = "GreyNoise API key"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        key = self.credentials["key"]
        headers = {"key": key}
        try:
            resp = await client.get(
                "https://api.greynoise.io/v2/meta/ping", headers=headers
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json()
            detail = (
                f"offering={data.get('offering', '?')} "
                f"expiration={data.get('expiration', '?')}"
            )
            return self.valid(detail, **data)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
