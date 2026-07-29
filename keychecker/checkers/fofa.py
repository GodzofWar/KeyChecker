"""FOFA API credential checker (email + key)."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class FofaChecker(BaseChecker):
    name = "fofa"
    display_name = "FOFA"
    fields = ("email", "key")
    env_vars = {"email": "FOFA_EMAIL", "key": "FOFA_KEY"}
    help = "FOFA credentials as EMAIL:KEY"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        email = self.credentials["email"]
        key = self.credentials["key"]
        try:
            resp = await client.get(
                "https://fofa.info/api/v1/info/my",
                params={"email": email, "key": key},
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        # FOFA returns HTTP 200 with an "error" flag in the body even for
        # bad credentials, so inspect the JSON rather than the status code.
        try:
            data = resp.json()
        except ValueError:
            return self.error(f"non-JSON response (HTTP {resp.status_code})")

        if resp.status_code == 200 and not data.get("error"):
            detail = (
                f"vip_level={data.get('vip_level', data.get('vip', '?'))} "
                f"points={data.get('fofa_point', '?')} "
                f"remain_api_query={data.get('remain_api_query', '?')}"
            )
            return self.valid(detail, **data)
        return self.invalid(data.get("errmsg", f"HTTP {resp.status_code}"))
