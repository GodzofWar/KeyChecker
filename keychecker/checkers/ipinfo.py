"""IPinfo API token checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class IPinfoChecker(BaseChecker):
    name = "ipinfo"
    display_name = "IPinfo"
    fields = ("token",)
    env_vars = {"token": "IPINFO_TOKEN"}
    help = "IPinfo API token"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        token = self.credentials["token"]
        try:
            resp = await client.get(
                "https://ipinfo.io/me", params={"token": token}
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json()
            requests = data.get("requests", {})
            detail = (
                f"requests={requests.get('month', '?')}/{requests.get('limit', '?')} "
                f"remaining={requests.get('remaining', '?')}"
            )
            return self.valid(detail, **data)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
