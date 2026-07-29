"""Collect credentials from a config file, environment, and CLI flags.

Each source contributes zero or more :class:`Job` objects. The config file
may list *multiple* credential sets per service (so a whole pile of keys can
be checked in one run); env vars and CLI flags contribute at most one set per
service.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import yaml

from .checkers import REGISTRY
from .models import Job


def _mask(value: str) -> str:
    """Mask a secret for display, keeping the last 4 characters."""
    if not value:
        return "<empty>"
    if len(value) <= 4:
        return "*" * len(value)
    return f"{'*' * (len(value) - 4)}{value[-4:]}"


def _label(service: str, credentials: Dict[str, str]) -> str:
    """Build a display label that identifies a credential without leaking it."""
    cls = REGISTRY[service]
    # Prefer a human-identifying, non-secret field if present.
    for ident in ("email", "id", "username"):
        if ident in credentials and ident != cls.fields[-1]:
            return f"{credentials[ident]} ({_mask(credentials[cls.fields[-1]])})"
    return _mask(credentials[cls.fields[-1]])


def _normalize(service: str, raw: Any) -> List[Dict[str, str]]:
    """Normalize a config entry into a list of credential dicts."""
    cls = REGISTRY[service]
    entries = raw if isinstance(raw, list) else [raw]
    out: List[Dict[str, str]] = []
    for entry in entries:
        if isinstance(entry, str):
            # Shorthand: a bare string maps to the single-field checker,
            # or colon-separated values in field order.
            parts = entry.split(":")
            entry = dict(zip(cls.fields, parts))
        creds = {f: str(entry[f]) for f in cls.fields if f in entry}
        missing = [f for f in cls.fields if f not in creds]
        if missing:
            raise ValueError(
                f"{service}: missing credential field(s): {', '.join(missing)}"
            )
        out.append(creds)
    return out


def load_from_file(path: str) -> List[Job]:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError("config file must be a mapping of service -> credentials")

    jobs: List[Job] = []
    for service, raw in data.items():
        if service not in REGISTRY:
            raise ValueError(f"unknown service in config: {service!r}")
        for creds in _normalize(service, raw):
            jobs.append(
                Job(service, creds, _label(service, creds), source="config")
            )
    return jobs


def load_from_env() -> List[Job]:
    jobs: List[Job] = []
    for service, cls in REGISTRY.items():
        values = {}
        for field, env_name in cls.env_vars.items():
            val = os.environ.get(env_name)
            if val:
                values[field] = val
        if len(values) == len(cls.fields):
            jobs.append(Job(service, values, _label(service, values), source="env"))
    return jobs


def load_from_cli(cli_values: Dict[str, str]) -> List[Job]:
    """Build jobs from parsed CLI flags (service name -> raw value)."""
    jobs: List[Job] = []
    for service, raw in cli_values.items():
        if raw is None:
            continue
        creds = _normalize(service, raw)[0]
        jobs.append(Job(service, creds, _label(service, creds), source="cli"))
    return jobs


def gather_jobs(
    config_path: Optional[str],
    cli_values: Dict[str, str],
    use_env: bool = True,
    only: Optional[List[str]] = None,
) -> List[Job]:
    """Merge jobs from all sources, optionally filtered to ``only`` services."""
    jobs: List[Job] = []
    if config_path:
        jobs.extend(load_from_file(config_path))
    if use_env:
        jobs.extend(load_from_env())
    jobs.extend(load_from_cli(cli_values))

    if only:
        allowed = set(only)
        jobs = [j for j in jobs if j.service in allowed]
    return jobs
