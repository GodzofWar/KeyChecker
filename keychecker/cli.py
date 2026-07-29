"""Command-line interface for KeyChecker."""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import List, Optional

from . import __version__
from .checkers import REGISTRY
from .config import gather_jobs
from .models import ERROR, INVALID
from .output import render_json, render_table
from .runner import run_checks


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keychecker",
        description=(
            "Check the validity (and quota/plan) of API keys for recon "
            "services like Shodan, Censys, and FOFA."
        ),
        epilog=(
            "Keys can come from a config file (--config), environment "
            "variables, and/or per-service CLI flags below. Multi-field "
            "services take colon-separated values, e.g. --censys ID:SECRET."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-c", "--config", metavar="PATH", help="YAML config file with keys per service"
    )
    parser.add_argument(
        "--no-env",
        action="store_true",
        help="do not read keys from environment variables",
    )
    parser.add_argument(
        "--only",
        metavar="SERVICE",
        action="append",
        choices=sorted(REGISTRY),
        help="only check the named service(s); repeatable",
    )
    parser.add_argument(
        "--concurrency", type=int, default=10, help="max concurrent checks (default 10)"
    )
    parser.add_argument(
        "--timeout", type=float, default=15.0, help="per-request timeout in seconds"
    )
    parser.add_argument("--json", action="store_true", help="output JSON instead of a table")
    parser.add_argument(
        "--list", action="store_true", help="list supported services and exit"
    )

    # One flag per registered service, generated from the checker metadata.
    group = parser.add_argument_group("service keys")
    for name, cls in REGISTRY.items():
        group.add_argument(
            f"--{name}", metavar="VALUE", help=cls.help or f"{cls.display_name} key"
        )
    return parser


def _list_services(stream=sys.stdout) -> None:
    stream.write("Supported services:\n")
    for name, cls in REGISTRY.items():
        env = ", ".join(cls.env_vars.values())
        stream.write(f"  {name:<16} fields={':'.join(cls.fields):<12} env={env}\n")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

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
        return 2  # pragma: no cover (argparse exits)

    if not jobs:
        sys.stderr.write(
            "No credentials found. Provide keys via --config, environment "
            "variables, or per-service flags (see --help).\n"
        )
        return 2

    results = asyncio.run(
        run_checks(jobs, concurrency=args.concurrency, timeout=args.timeout)
    )

    if args.json:
        render_json(results)
    else:
        render_table(results)

    # Non-zero exit if anything was invalid or errored, for scripting.
    if any(r.status in (INVALID, ERROR) for r in results):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
