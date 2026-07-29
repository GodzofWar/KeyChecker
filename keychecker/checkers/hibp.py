"""Have I Been Pwned (HIBP) API key checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class HIBPChecker(BaseChecker):
    name = "hibp"
    display_name = "Have I Been Pwned"
    fields = ("key",)
    env_vars = {"key": "HIBP_API_KEY"}
    help = "Have I Been Pwned API key"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        key = self.credentials["key"]
        # HIBP requires an API key header and a descriptive user-agent
        # (the shared client already sends a KeyChecker user-agent).
        headers = {"hibp-api-key": key}
        try:
            resp = await client.get(
                "https://haveibeenpwned.com/api/v3/subscription/status",
                headers=headers,
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json()
            detail = (
                f"plan={data.get('SubscriptionName', '?')} "
                f"rpm={data.get('Rpm', '?')} "
                f"until={data.get('SubscribedUntil', '?')}"
            )
            return self.valid(detail, **data)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
