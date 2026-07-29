"""Render check results as a table or JSON."""

from __future__ import annotations

import json
import os
import sys
from typing import List

from .checkers import REGISTRY
from .models import CheckResult, ERROR, INVALID, VALID

_RESET = "\033[0m"
_SYMBOLS = {VALID: "OK", INVALID: "BAD", ERROR: "ERR"}
# Keyed by the displayed symbol so the STATUS column can be colorized directly.
_COLORS = {
    "OK": "\033[32m",  # green
    "BAD": "\033[31m",  # red
    "ERR": "\033[33m",  # yellow
}


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _display_name(service: str) -> str:
    cls = REGISTRY.get(service)
    return cls.display_name if cls else service


def render_table(results: List[CheckResult], stream=sys.stdout) -> None:
    if not results:
        stream.write("No credentials to check.\n")
        return

    color = _use_color(stream)
    rows = []
    for r in results:
        rows.append((_display_name(r.service), r.label, r.status, r.detail))

    headers = ("SERVICE", "ACCOUNT", "STATUS", "DETAILS")
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    # Keep the details column from running away.
    widths[3] = min(widths[3], 70)

    def fmt_row(cells, colorize_status=False):
        out = []
        for i, cell in enumerate(cells):
            text = str(cell)
            if i == 3 and len(text) > widths[3]:
                text = text[: widths[3] - 1] + "…"
            padded = text.ljust(widths[i])
            if colorize_status and i == 2 and color:
                padded = f"{_COLORS.get(cell, '')}{padded}{_RESET}"
            out.append(padded)
        return "  ".join(out)

    stream.write(fmt_row(headers) + "\n")
    stream.write("  ".join("-" * w for w in widths) + "\n")
    for row in rows:
        status = row[2]
        ordered = (row[0], row[1], _SYMBOLS.get(status, status), row[3])
        stream.write(fmt_row(ordered, colorize_status=True) + "\n")

    valid = sum(1 for r in results if r.status == VALID)
    invalid = sum(1 for r in results if r.status == INVALID)
    errored = sum(1 for r in results if r.status == ERROR)
    stream.write(
        f"\n{len(results)} checked: {valid} valid, {invalid} invalid, {errored} error\n"
    )


def render_json(results: List[CheckResult], stream=sys.stdout) -> None:
    json.dump([r.to_dict() for r in results], stream, indent=2)
    stream.write("\n")
