"""Shodan API key checker."""

from __future__ import annotations

import httpx

from ..models import CheckResult
from .base import BaseChecker


class ShodanChecker(BaseChecker):
    name = "shodan"
    display_name = "Shodan"
    fields = ("key",)
    env_vars = {"key": "SHODAN_API_KEY"}
    help = "Shodan API key"

    # Shodan keys are 32 alphanumeric characters. They leak most often
    # embedded in api.shodan.io request URLs or passed to the official
    # Python SDK (`shodan.Shodan("...")`), not just as SHODAN_API_KEY=...
    hunt_queries = ("api.shodan.io", "shodan.Shodan")
    # The trailing (?![A-Za-z0-9]) keeps a longer token from matching as a
    # 32-char prefix (a 40-char value should not be mistaken for a key).
    hunt_patterns = (
        # ...api.shodan.io/shodan/host/search?key=<KEY>...
        r'api\.shodan\.io[^\s"\'<>]*[?&]key=([A-Za-z0-9]{32})(?![A-Za-z0-9])',
        # shodan.Shodan("<KEY>") / Shodan('<KEY>')
        r'[Ss]hodan\(\s*["\']([A-Za-z0-9]{32})["\']',
        # shodan_api_key / SHODAN-API-KEY / shodankey : "<KEY>"
        r'shodan[_\-]?api[_\-]?key["\']?\s*[:=,]\s*["\']?([A-Za-z0-9]{32})(?![A-Za-z0-9])',
        r'shodan[_\-]?key["\']?\s*[:=,]\s*["\']?([A-Za-z0-9]{32})(?![A-Za-z0-9])',
    )
    secret_regex = r"[A-Za-z0-9]{32}"

    async def check(self, client: httpx.AsyncClient) -> CheckResult:
        key = self.credentials["key"]
        try:
            resp = await client.get(
                "https://api.shodan.io/api-info", params={"key": key}
            )
        except httpx.HTTPError as exc:
            return self.error(f"request failed: {exc}")

        if resp.status_code == 200:
            data = resp.json()
            plan = data.get("plan", "?")
            detail = (
                f"plan={plan} "
                f"query_credits={data.get('query_credits')} "
                f"scan_credits={data.get('scan_credits')}"
            )
            return self.valid(detail, **data)
        if resp.status_code in (401, 403):
            return self.invalid(f"unauthorized (HTTP {resp.status_code})")
        return self.error(f"unexpected HTTP {resp.status_code}: {resp.text[:200]}")
