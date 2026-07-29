"""Onyphe API key checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class OnypheChecker(BaseChecker):
    name = "onyphe"
    display_name = "Onyphe"
    fields = ("key",)
    env_vars = {"key": "ONYPHE_API_KEY"}
    help = "Onyphe API key"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        key = self.credentials["key"]
        headers = {"Authorization": f"apikey {key}"}
        try:
            resp = await client.get(
                "https://www.onyphe.io/api/v2/user", headers=headers
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        try:
            data = resp.json()
        except ValueError:
            data = {}

        if resp.status_code == 200 and data.get("status") == "ok":
            results = data.get("results") or [{}]
            info = results[0]
            detail = (
                f"tier={info.get('tier', '?')} "
                f"credits={info.get('credits', '?')} "
                f"email={info.get('email', '?')}"
            )
            return self.valid(detail, **info)
        if resp.status_code in (401, 403, 429):
            return self.invalid(
                data.get("text", f"unauthorized (HTTP {resp.status_code})")
            )
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
