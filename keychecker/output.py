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


def _mask_secret(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "*" * (len(value) - 2)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def render_hits_table(hits, stream=sys.stdout, show_secrets: bool = False) -> None:
    """Render secret-hunt results as a table."""
    if not hits:
        stream.write("No candidate secrets found.\n")
        return

    color = _use_color(stream)
    rows = []
    for h in hits:
        secret = h.secret if show_secrets else _mask_secret(h.secret)
        status = _SYMBOLS.get(h.validation, "-") if h.validation else "-"
        rows.append(
            (_display_name(h.service), h.repository, h.path, secret, status, h.url)
        )

    headers = ("SERVICE", "REPOSITORY", "PATH", "SECRET", "VALID", "URL")
    status_col = 4
    url_col = 5
    widths = [len(x) for x in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    widths[1] = min(widths[1], 30)
    widths[2] = min(widths[2], 30)

    def fmt(cells, colorize=False):
        out = []
        for i, cell in enumerate(cells):
            text = str(cell)
            if i in (1, 2) and len(text) > widths[i]:
                text = "…" + text[-(widths[i] - 1) :]
            # The URL is the last column; leave it full-length (unpadded) so it
            # stays clickable and copy-pasteable.
            if i == url_col:
                out.append(text)
                continue
            padded = text.ljust(widths[i])
            if colorize and i == status_col and color and cell in _COLORS:
                padded = f"{_COLORS[cell]}{padded}{_RESET}"
            out.append(padded)
        return "  ".join(out)

    stream.write(fmt(headers) + "\n")
    stream.write("  ".join("-" * w for w in widths) + "\n")
    for row in rows:
        stream.write(fmt(row, colorize=True) + "\n")

    validated = [h for h in hits if h.validation == VALID]
    stream.write(f"\n{len(hits)} candidate secret(s) found")
    if validated:
        stream.write(f", {len(validated)} confirmed VALID")
    stream.write("\n")
    if not show_secrets:
        stream.write("(secrets masked; pass --show-secrets to reveal)\n")


def render_hits_json(hits, stream=sys.stdout, show_secrets: bool = False) -> None:
    payload = []
    for h in hits:
        d = h.to_dict()
        if not show_secrets:
            d["secret"] = _mask_secret(h.secret)
        payload.append(d)
    json.dump(payload, stream, indent=2)
    stream.write("\n")
