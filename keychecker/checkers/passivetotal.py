"""PassiveTotal (RiskIQ) API credential checker (username + key)."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class PassiveTotalChecker(BaseChecker):
    name = "passivetotal"
    display_name = "PassiveTotal"
    fields = ("username", "key")
    env_vars = {"username": "PASSIVETOTAL_USERNAME", "key": "PASSIVETOTAL_API_KEY"}
    help = "PassiveTotal credentials as USERNAME:API_KEY"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        username = self.credentials["username"]
        key = self.credentials["key"]
        try:
            resp = await client.get(
                "https://api.passivetotal.org/v2/account/quota",
                auth=(username, key),
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json()
            quotas = data.get("quotas", {})
            search = quotas.get("search_api", {})
            detail = (
                f"search_api={search.get('used', '?')}/{search.get('limit', '?')}"
            )
            return self.valid(detail, **data)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
