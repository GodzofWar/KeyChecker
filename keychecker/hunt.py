"""Hunt for leaked API keys in public GitHub code.

This uses the authenticated GitHub code-search API to find source that mentions
the secret-shaped environment variables KeyChecker already knows about (e.g.
``SHODAN_API_KEY``), extracts candidate secrets from the matched fragments, and
can optionally validate them with the existing service checkers.

Intended for defensive use — monitoring for *your own* leaked credentials and
authorized security research. Only act on secrets you are permitted to handle.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx

from .checkers import REGISTRY
from .models import CheckResult

GITHUB_CODE_SEARCH = "https://api.github.com/search/code"

# Substrings that mark an obvious placeholder rather than a real secret.
_PLACEHOLDER_MARKERS = (
    "your",
    "example",
    "changeme",
    "xxxx",
    "placeholder",
    "dummy",
    "insert",
    "here",
    "todo",
    "apikey",
    "api_key",
    "token",
    "secret",
    "none",
    "null",
)


@dataclass
class SecretHit:
    """A candidate leaked secret found in a GitHub search result."""

    service: str
    keyword: str
    repository: str
    path: str
    url: str
    secret: str
    validation: Optional[str] = None  # valid / invalid / error / None
    detail: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "service": self.service,
            "keyword": self.keyword,
            "repository": self.repository,
            "path": self.path,
            "url": self.url,
            "secret": self.secret,
            "validation": self.validation,
            "detail": self.detail,
        }


def default_dorks(only: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """Build search keywords per service from each checker's env-var names.

    The environment variables people use to store a key (``SHODAN_API_KEY``,
    ``VT_API_KEY``, ...) are exactly what leaked config tends to name them, so
    they make high-signal search terms — and this stays in sync automatically
    as new checkers are added.
    """
    dorks: Dict[str, List[str]] = {}
    for name, cls in REGISTRY.items():
        if only and name not in only:
            continue
        dorks[name] = list(cls.env_vars.values())
    return dorks


def _extraction_regex(keyword: str) -> "re.Pattern[str]":
    # KEYWORD = "value" / KEYWORD: 'value' / "KEYWORD","value"
    return re.compile(
        re.escape(keyword) + r'["\']?\s*[:=,]\s*["\']?([A-Za-z0-9_\-\.=+/]{16,100})',
        re.IGNORECASE,
    )


def _looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    if any(marker in low for marker in _PLACEHOLDER_MARKERS):
        return True
    # e.g. "xxxxxxxx", "aaaaaaaa", "0000..." — one repeated character.
    if len(set(value)) <= 2:
        return True
    return False


def extract_secrets(text: str, keyword: str) -> List[str]:
    """Pull candidate secret values assigned to ``keyword`` out of ``text``."""
    found = []
    for match in _extraction_regex(keyword).finditer(text):
        candidate = match.group(1)
        if _looks_like_placeholder(candidate):
            continue
        found.append(candidate)
    return found


class GitHubSearcher:
    """Thin wrapper over the GitHub code-search API with rate-limit handling."""

    def __init__(self, token: str, spacing: float = 2.0):
        self.token = token
        self.spacing = spacing  # seconds between search requests (10/min limit)

    @property
    def headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.text-match+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def search(
        self, client: httpx.AsyncClient, query: str, max_results: int
    ) -> List[dict]:
        items: List[dict] = []
        page = 1
        per_page = min(100, max_results)
        while len(items) < max_results:
            resp = await client.get(
                GITHUB_CODE_SEARCH,
                headers=self.headers,
                params={"q": query, "per_page": per_page, "page": page},
            )
            if resp.status_code == 403 and "rate limit" in resp.text.lower():
                retry_after = int(resp.headers.get("Retry-After", "10"))
                await asyncio.sleep(min(retry_after, 60))
                continue
            if resp.status_code != 200:
                break
            batch = resp.json().get("items", [])
            items.extend(batch)
            if len(batch) < per_page:
                break
            page += 1
            await asyncio.sleep(self.spacing)
        return items[:max_results]


def _fragments(item: dict) -> List[str]:
    """Collect the searchable text from a code-search item."""
    texts = [m.get("fragment", "") for m in item.get("text_matches", [])]
    if not texts:
        texts = [item.get("name", "") + " " + item.get("path", "")]
    return texts


async def hunt(
    token: str,
    dorks: Dict[str, List[str]],
    raw_query: Optional[str] = None,
    qualifiers: str = "",
    max_results: int = 30,
    timeout: float = 20.0,
    spacing: float = 2.0,
) -> List[SecretHit]:
    """Run the configured searches and return deduplicated candidate hits."""
    searcher = GitHubSearcher(token, spacing=spacing)
    seen = set()
    hits: List[SecretHit] = []

    # (service, keyword, query) tuples to execute.
    plan = []
    if raw_query:
        # A raw query is searched verbatim; try every service's extractors on it.
        q = f"{raw_query} {qualifiers}".strip()
        plan.append((None, None, q))
    else:
        for service, keywords in dorks.items():
            for kw in keywords:
                q = f'"{kw}" {qualifiers}'.strip()
                plan.append((service, kw, q))

    async with httpx.AsyncClient(
        timeout=timeout, headers={"User-Agent": "KeyChecker/0.1"}
    ) as client:
        for service, keyword, query in plan:
            items = await searcher.search(client, query, max_results)
            keywords_for_extraction = (
                [keyword]
                if keyword
                else [k for kws in dorks.values() for k in kws]
            )
            svc_by_keyword = {
                k: s for s, kws in dorks.items() for k in kws
            }
            for item in items:
                repo = item.get("repository", {}).get("full_name", "?")
                path = item.get("path", "?")
                url = item.get("html_url", "")
                for text in _fragments(item):
                    for kw in keywords_for_extraction:
                        for secret in extract_secrets(text, kw):
                            svc = service or svc_by_keyword.get(kw, "unknown")
                            dedupe_key = (svc, repo, path, secret)
                            if dedupe_key in seen:
                                continue
                            seen.add(dedupe_key)
                            hits.append(
                                SecretHit(
                                    service=svc,
                                    keyword=kw,
                                    repository=repo,
                                    path=path,
                                    url=url,
                                    secret=secret,
                                )
                            )
    return hits


async def validate_hits(
    hits: List[SecretHit], concurrency: int = 10, timeout: float = 15.0
) -> List[SecretHit]:
    """Validate hits for single-field key services using the real checkers.

    Multi-field services (e.g. Censys id+secret) can't be validated from a
    single found value, so those are left unvalidated for manual follow-up.
    """
    sem = asyncio.Semaphore(concurrency)

    async def _one(hit: SecretHit, client: httpx.AsyncClient) -> None:
        cls = REGISTRY.get(hit.service)
        if cls is None or len(cls.fields) != 1:
            hit.detail = "not auto-validatable (multi-field or unknown service)"
            return
        creds = {cls.fields[0]: hit.secret}
        checker = cls(creds)
        async with sem:
            try:
                result: CheckResult = await checker.check(client)
            except Exception as exc:  # defensive
                hit.validation = "error"
                hit.detail = f"validation failed: {exc}"
                return
        hit.validation = result.status
        hit.detail = result.detail

    async with httpx.AsyncClient(
        timeout=timeout, headers={"User-Agent": "KeyChecker/0.1"}
    ) as client:
        await asyncio.gather(*(_one(h, client) for h in hits))
    return hits
