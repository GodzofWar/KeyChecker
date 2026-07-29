"""SecurityTrails API key checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class SecurityTrailsChecker(BaseChecker):
    name = "securitytrails"
    display_name = "SecurityTrails"
    fields = ("key",)
    env_vars = {"key": "SECURITYTRAILS_API_KEY"}
    help = "SecurityTrails API key"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        key = self.credentials["key"]
        headers = {"APIKEY": key}
        try:
            resp = await client.get(
                "https://api.securitytrails.com/v1/account/usage", headers=headers
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json()
            detail = (
                f"used={data.get('current_monthly_usage', '?')} "
                f"limit={data.get('allowed_monthly_usage', '?')}"
            )
            return self.valid(detail, **data)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
