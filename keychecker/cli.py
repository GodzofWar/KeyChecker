"""Command-line interface for KeyChecker."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import List, Optional

from . import __version__
from .checkers import REGISTRY
from .config import gather_jobs
from .hunt import hunt, validate_hits
from .models import ERROR, INVALID, VALID
from .output import (
    render_hits_json,
    render_hits_table,
    render_json,
    render_table,
)
from .runner import run_checks

_SUBCOMMANDS = ("check", "hunt")


def _add_check_parser(sub) -> None:
    p = sub.add_parser(
        "check",
        help="check whether API keys are valid (default command)",
        description=(
            "Check the validity (and quota/plan) of API keys for recon "
            "services like Shodan, Censys, and FOFA."
        ),
        epilog=(
            "Keys can come from a config file (--config), environment "
            "variables, and/or per-service CLI flags. Multi-field services "
            "take colon-separated values, e.g. --censys ID:SECRET."
        ),
    )
    p.add_argument("-c", "--config", metavar="PATH", help="YAML config file")
    p.add_argument(
        "--no-env", action="store_true", help="do not read keys from environment"
    )
    p.add_argument(
        "--only",
        metavar="SERVICE",
        action="append",
        choices=sorted(REGISTRY),
        help="only check the named service(s); repeatable",
    )
    p.add_argument("--concurrency", type=int, default=10, help="max concurrent checks")
    p.add_argument("--timeout", type=float, default=15.0, help="per-request timeout (s)")
    p.add_argument("--json", action="store_true", help="output JSON instead of a table")
    p.add_argument("--list", action="store_true", help="list supported services and exit")

    group = p.add_argument_group("service keys")
    for name, cls in REGISTRY.items():
        group.add_argument(
            f"--{name}", metavar="VALUE", help=cls.help or f"{cls.display_name} key"
        )


def _add_hunt_parser(sub) -> None:
    p = sub.add_parser(
        "hunt",
        help="hunt for leaked API keys in public GitHub code",
        description=(
            "Search public GitHub code for leaked recon API keys and "
            "optionally validate the ones found. For defensive use: "
            "monitoring for your own leaked credentials and authorized "
            "security research only."
        ),
    )
    p.add_argument(
        "query",
        nargs="?",
        help="raw GitHub code-search query (overrides the built-in dorks)",
    )
    p.add_argument(
        "--github-token",
        metavar="TOKEN",
        help="GitHub token (defaults to $GITHUB_TOKEN); required",
    )
    p.add_argument("--org", metavar="ORG", help="scope search to a GitHub org")
    p.add_argument("--user", metavar="USER", help="scope search to a GitHub user")
    p.add_argument("--repo", metavar="OWNER/REPO", help="scope search to one repo")
    p.add_argument(
        "--only",
        metavar="SERVICE",
        action="append",
        choices=sorted(REGISTRY),
        help="only hunt for the named service(s); repeatable",
    )
    p.add_argument(
        "--max-results", type=int, default=30, help="max results per query (default 30)"
    )
    p.add_argument(
        "--validate",
        action="store_true",
        help="validate found single-field keys against their service",
    )
    p.add_argument(
        "--show-secrets",
        action="store_true",
        help="print full secrets instead of masking them",
    )
    p.add_argument("--concurrency", type=int, default=10, help="max concurrent checks")
    p.add_argument("--timeout", type=float, default=20.0, help="per-request timeout (s)")
    p.add_argument("--json", action="store_true", help="output JSON instead of a table")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keychecker",
        description=(
            "Validate recon/OSINT API keys and hunt for leaked ones on GitHub."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    _add_check_parser(sub)
    _add_hunt_parser(sub)
    return parser


def _list_services(stream=sys.stdout) -> None:
    stream.write("Supported services:\n")
    for name, cls in REGISTRY.items():
        env = ", ".join(cls.env_vars.values())
        stream.write(f"  {name:<16} fields={':'.join(cls.fields):<12} env={env}\n")


def _run_check(args, parser) -> int:
    if args.list:
        _list_services()
        return 0

    cli_values = {name: getattr(args, name) for name in REGISTRY}
    try:
        jobs = gather_jobs(
            config_path=args.config,
            cli_values=cli_values,
            use_env=not args.no_env,
            only=args.only,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
        return 2  # pragma: no cover

    if not jobs:
        sys.stderr.write(
            "No credentials found. Provide keys via --config, environment "
            "variables, or per-service flags (see 'keychecker check --help').\n"
        )
        return 2

    results = asyncio.run(
        run_checks(jobs, concurrency=args.concurrency, timeout=args.timeout)
    )
    if args.json:
        render_json(results)
    else:
        render_table(results)

    if any(r.status in (INVALID, ERROR) for r in results):
        return 1
    return 0


def _build_qualifiers(args) -> str:
    parts = []
    if args.org:
        parts.append(f"org:{args.org}")
    if args.user:
        parts.append(f"user:{args.user}")
    if args.repo:
        parts.append(f"repo:{args.repo}")
    return " ".join(parts)


def _run_hunt(args) -> int:
    token = args.github_token or os.environ.get("GITHUB_TOKEN")
    if not token:
        sys.stderr.write(
            "A GitHub token is required for hunting. Pass --github-token or set "
            "$GITHUB_TOKEN.\n"
        )
        return 2

    hits = asyncio.run(
        hunt(
            token=token,
            only=args.only,
            raw_query=args.query,
            qualifiers=_build_qualifiers(args),
            max_results=args.max_results,
            timeout=args.timeout,
        )
    )

    if args.validate and hits:
        hits = asyncio.run(
            validate_hits(hits, concurrency=args.concurrency, timeout=args.timeout)
        )

    if args.json:
        render_hits_json(hits, show_secrets=args.show_secrets)
    else:
        render_hits_table(hits, show_secrets=args.show_secrets)

    if any(h.validation == VALID for h in hits):
        return 1
    return 0


def _normalize_argv(argv: List[str]) -> List[str]:
    """Default to the ``check`` subcommand for backward compatibility."""
    if not argv:
        return ["check"]
    first = argv[0]
    if first in _SUBCOMMANDS or first in ("-h", "--help", "--version"):
        return argv
    return ["check"] + argv


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    argv = _normalize_argv(argv)

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "hunt":
        return _run_hunt(args)
    return _run_check(args, parser)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
