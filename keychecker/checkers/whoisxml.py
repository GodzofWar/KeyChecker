"""WhoisXML API key checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class WhoisXMLChecker(BaseChecker):
    name = "whoisxml"
    display_name = "WhoisXML API"
    fields = ("key",)
    env_vars = {"key": "WHOISXML_API_KEY"}
    help = "WhoisXML API key"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        key = self.credentials["key"]
        try:
            resp = await client.get(
                "https://user.whoisxmlapi.com/service/account-balance",
                params={"apiKey": key, "output_format": "JSON"},
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        try:
            data = resp.json()
        except ValueError:
            return self.error(f"non-JSON response (HTTP {resp.status_code})")

        # A valid key returns a "data" list of per-product balances.
        if resp.status_code == 200 and isinstance(data.get("data"), list):
            products = data["data"]
            summary = ", ".join(
                f"{p.get('product')}={p.get('credits')}" for p in products[:3]
            )
            return self.valid(summary or "ok", products=products)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        # WhoisXML reports bad keys as a message payload with HTTP 200.
        msg = data.get("messages") or data.get("message")
        if msg:
            return self.invalid(str(msg))
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
