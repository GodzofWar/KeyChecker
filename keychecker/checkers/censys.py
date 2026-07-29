"""Censys Search API credential checker (API ID + secret)."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class CensysChecker(BaseChecker):
    name = "censys"
    display_name = "Censys"
    fields = ("id", "secret")
    env_vars = {"id": "CENSYS_API_ID", "secret": "CENSYS_API_SECRET"}
    help = "Censys credentials as API_ID:API_SECRET"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        api_id = self.credentials["id"]
        secret = self.credentials["secret"]
        try:
            resp = await client.get(
                "https://search.censys.io/api/v2/account",
                auth=(api_id, secret),
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json()
            quota = data.get("quota", {})
            detail = (
                f"email={data.get('email', '?')} "
                f"quota={quota.get('used')}/{quota.get('allowance')} "
                f"resets={quota.get('resets_at', '?')}"
            )
            return self.valid(detail, **data)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
