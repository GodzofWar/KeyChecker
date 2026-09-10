"""Base class and helpers for service checkers."""

from __future__ import annotations

from typing import ClassVar, Dict, Optional, Sequence

import httpx

from ..models import CheckResult, ERROR, INVALID, VALID


class BaseChecker:
    """Subclass this to add a new service.

    Declare ``name``, the credential ``fields`` (in the order a user would
    pass them on the CLI), and ``env_vars`` mapping each field to the
    environment variable it can be read from. Implement :meth:`check`.
    """

    #: Short, lowercase service identifier used in config keys and CLI flags.
    name: ClassVar[str] = ""

    #: Human-friendly display name.
    display_name: ClassVar[str] = ""

    #: Credential field names required, in CLI order (e.g. ("id", "secret")).
    fields: ClassVar[Sequence[str]] = ("key",)

    #: Mapping of credential field -> environment variable name.
    env_vars: ClassVar[Dict[str, str]] = {}

    #: One-line help shown next to the generated CLI flag.
    help: ClassVar[str] = ""

    # -- leak-hunting metadata (optional) -------------------------------
    #
    # The ``hunt`` subcommand searches GitHub for each service's env-var
    # names by default. A service can widen that net by declaring extra,
    # higher-signal search terms and extraction patterns for the shapes its
    # keys actually leak in (URLs, SDK idioms, alternate variable names).

    #: Extra GitHub code-search terms to look for, beyond the env-var names.
    hunt_queries: ClassVar[Sequence[str]] = ()

    #: Extra extraction regexes, each with ONE capture group = the secret.
    #: Applied (case-insensitively) to every search result for this service.
    hunt_patterns: ClassVar[Sequence[str]] = ()

    #: Optional regex a candidate must fully match to be kept. Use this to
    #: pin a service's known key shape (e.g. Shodan's 32 alphanumerics) so
    #: broad matches don't yield junk. ``None`` means "no shape constraint".
    secret_regex: ClassVar[Optional[str]] = None

    def __init__(self, credentials: Dict[str, str], label: str = ""):
        self.credentials = credentials
        self.label = label

    async def check(self, client: httpx.AsyncClient) -> CheckResult:  # pragma: no cover
        raise NotImplementedError

    # -- result helpers -------------------------------------------------

    def _result(self, status: str, detail: str = "", **metadata) -> CheckResult:
        return CheckResult(
            service=self.name,
            label=self.label,
            status=status,
            detail=detail,
            metadata=metadata,
        )

    def valid(self, detail: str = "", **metadata) -> CheckResult:
        return self._result(VALID, detail, **metadata)

    def invalid(self, detail: str = "", **metadata) -> CheckResult:
        return self._result(INVALID, detail, **metadata)

    def error(self, detail: str = "", **metadata) -> CheckResult:
        return self._result(ERROR, detail, **metadata)
