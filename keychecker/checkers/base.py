"""Base class and helpers for service checkers."""

from __future__ import annotations

from typing import ClassVar, Dict, Sequence

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
