"""Hunt for leaked API keys in public GitHub code.

This uses the authenticated GitHub code-search API to find source that mentions
the secret-shaped environment variables KeyChecker already knows about (e.g.
``SHODAN_API_KEY``), extracts candidate secrets from the matched fragments, and
can optionally validate them with the existing service checkers.

On top of the env-var dorks, a checker can declare service-specific
``hunt_queries``/``hunt_patterns``/``secret_regex`` (see ``BaseChecker``) to
catch the shapes its keys really leak in — Shodan keys, for instance, show up
inside ``api.shodan.io`` request URLs and ``shodan.Shodan("...")`` SDK calls,
not only as ``SHODAN_API_KEY=...``.

Intended for defensive use — monitoring for *your own* leaked credentials and
authorized security research. Only act on secrets you are permitted to handle.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Pattern

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
    as new checkers are added. Services that declare extra ``hunt_queries``
    contribute those too.
    """
    dorks: Dict[str, List[str]] = {}
    for name, cls in REGISTRY.items():
        if only and name not in only:
            continue
        terms: List[str] = list(cls.env_vars.values())
        for extra in getattr(cls, "hunt_queries", ()):
            if extra not in terms:
                terms.append(extra)
        dorks[name] = terms
    return dorks


def _extraction_regex(keyword: str) -> "Pattern[str]":
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
    return _extract(text, [_extraction_regex(keyword)])


def _extract(
    text: str,
    patterns: List["Pattern[str]"],
    shape: Optional["Pattern[str]"] = None,
) -> List[str]:
    """Run each extraction ``pattern`` over ``text`` and keep real-looking hits.

    ``shape``, when given, is a regex a candidate must fully match to be kept —
    used to pin a service's known key format.
    """
    found: List[str] = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            candidate = match.group(1)
            if _looks_like_placeholder(candidate):
                continue
            if shape is not None and not shape.fullmatch(candidate):
                continue
            if candidate not in found:
                found.append(candidate)
    return found


@dataclass
class ServiceProbe:
    """How to hunt for one service: what to search, and how to extract."""

    service: str
    queries: List[str]
    patterns: List["Pattern[str]"]
    shape: Optional["Pattern[str]"] = None


def build_probes(only: Optional[List[str]] = None) -> List[ServiceProbe]:
    """Assemble the per-service search terms and extraction patterns.

    Each service contributes its env-var names (searched and extracted
    generically) plus any service-specific ``hunt_queries``/``hunt_patterns``
    and an optional ``secret_regex`` shape constraint.
    """
    probes: List[ServiceProbe] = []
    for name, cls in REGISTRY.items():
        if only and name not in only:
            continue

        queries: List[str] = []
        patterns: List["Pattern[str]"] = []
        for env_var in cls.env_vars.values():
            if env_var not in queries:
                queries.append(env_var)
            patterns.append(_extraction_regex(env_var))
        for extra in getattr(cls, "hunt_queries", ()):
            if extra not in queries:
                queries.append(extra)
        for raw in getattr(cls, "hunt_patterns", ()):
            patterns.append(re.compile(raw, re.IGNORECASE))

        shape_src = getattr(cls, "secret_regex", None)
        shape = re.compile(shape_src) if shape_src else None
        probes.append(
            ServiceProbe(
                service=name, queries=queries, patterns=patterns, shape=shape
            )
        )
    return probes


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


@dataclass
class _Search:
    """A single GitHub query and the probes whose patterns apply to it."""

    query: str  # the raw search term
    probes: List[ServiceProbe]
    quote: bool = True


def _plan_searches(
    probes: List[ServiceProbe], raw_query: Optional[str], qualifiers: str
) -> List[_Search]:
    if raw_query:
        # A raw query is searched verbatim; try every selected service's
        # extractors on whatever it turns up.
        return [_Search(query=raw_query.strip(), probes=probes, quote=False)]
    searches: List[_Search] = []
    for probe in probes:
        for term in probe.queries:
            searches.append(_Search(query=term, probes=[probe]))
    return searches


async def hunt(
    token: str,
    only: Optional[List[str]] = None,
    raw_query: Optional[str] = None,
    qualifiers: str = "",
    max_results: int = 30,
    timeout: float = 20.0,
    spacing: float = 2.0,
) -> List[SecretHit]:
    """Run the configured searches and return deduplicated candidate hits."""
    searcher = GitHubSearcher(token, spacing=spacing)
    probes = build_probes(only=only)
    searches = _plan_searches(probes, raw_query, qualifiers)

    seen = set()
    hits: List[SecretHit] = []

    async with httpx.AsyncClient(
        timeout=timeout, headers={"User-Agent": "KeyChecker/0.1"}
    ) as client:
        for search in searches:
            if search.quote:
                query = f'"{search.query}" {qualifiers}'.strip()
            else:
                query = f"{search.query} {qualifiers}".strip()
            items = await searcher.search(client, query, max_results)
            for item in items:
                repo = item.get("repository", {}).get("full_name", "?")
                path = item.get("path", "?")
                url = item.get("html_url", "")
                for text in _fragments(item):
                    for probe in search.probes:
                        for secret in _extract(text, probe.patterns, probe.shape):
                            dedupe_key = (probe.service, repo, path, secret)
                            if dedupe_key in seen:
                                continue
                            seen.add(dedupe_key)
                            hits.append(
                                SecretHit(
                                    service=probe.service,
                                    keyword=search.query,
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
