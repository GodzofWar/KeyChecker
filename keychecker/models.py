"""Shared data structures for KeyChecker."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

# Result statuses.
VALID = "valid"
INVALID = "invalid"
ERROR = "error"


@dataclass
class CheckResult:
    """Outcome of checking a single credential against a single service."""

    service: str
    label: str
    status: str
    detail: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == VALID

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service": self.service,
            "label": self.label,
            "status": self.status,
            "detail": self.detail,
            "metadata": self.metadata,
        }


@dataclass
class Job:
    """A single credential set queued for checking against one service."""

    service: str
    credentials: Dict[str, str]
    label: str
    source: str  # where the credential came from: "config", "env", "cli"
