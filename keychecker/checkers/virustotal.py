"""VirusTotal API key checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class VirusTotalChecker(BaseChecker):
    name = "virustotal"
    display_name = "VirusTotal"
    fields = ("key",)
    env_vars = {"key": "VT_API_KEY"}
    help = "VirusTotal API key"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        key = self.credentials["key"]
        headers = {"x-apikey": key}
        try:
            # Looking up the user by the key itself returns account + quota info.
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/users/{key}", headers=headers
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            detail = (
                f"user={attrs.get('first_name', data.get('id', '?'))} "
                f"type={attrs.get('user_type', '?')}"
            )
            return self.valid(detail, **attrs)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
