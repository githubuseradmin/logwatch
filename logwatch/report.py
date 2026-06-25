"""Render an analyser result dict as a human-readable terminal report.

The renderers here are pure string builders: they take the plain dict produced
by :mod:`logwatch.analyzers` and return a list of lines. They never touch the
analysers or do I/O, which keeps formatting trivially testable and lets the CLI
decide where the text goes (stdout, a file, a pipe).

Colour is applied through :mod:`logwatch.colors`, which becomes a no-op when
colour is disabled, so the same code path produces clean plain text for files.
"""

from __future__ import annotations

from typing import Dict, List

from . import colors

# Risk label -> colour function, used by the final risk banner.
_RISK_STYLE = {
    "LOW": colors.green,
    "MEDIUM": colors.yellow,
    "HIGH": colors.red,
}

# Human-friendly names for the suspicious-request categories.
_CATEGORY_LABELS = {
    "path_traversal": "Path traversal (../)",
    "sqli": "SQL injection pattern",
    "xss": "Cross-site scripting probe",
    "scanner_path": "Scanner / recon path",
    "oversized_query": "Oversized query string",
    "bad_method": "Unusual HTTP method",
}


def _human_bytes(num: int) -> str:
    """Format a byte count as a compact human string (e.g. 12.3 MB)."""
    value = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{num} B"


def _header(title: str) -> str:
    """Render a bold, underlined section header."""
    bar = "=" * len(title)
    return colors.bold(colors.cyan(title)) + "\n" + colors.dim(bar)


def _kv(label: str, value: str, width: int = 22) -> str:
    """Render an aligned ``label : value`` line."""
    return f"  {label.ljust(width)} {value}"


def _table(rows, headers, aligns=None) -> List[str]:
    """Render a simple fixed-width table as a list of lines.

    ``rows`` is a sequence of tuples already converted to strings; ``aligns`` is
    an optional per-column "l"/"r" alignment list.
    """
    if not rows:
        return ["  (none)"]
    cols = len(headers)
    aligns = aligns or ["l"] * cols
    widths = [len(h) for h in headers]
    for row in rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(str(row[i])))

    def fmt(cells, dim=False):
        parts = []
        for i in range(cols):
            cell = str(cells[i])
            cell = cell.rjust(widths[i]) if aligns[i] == "r" else cell.ljust(widths[i])
            parts.append(cell)
        line = "  " + "  ".join(parts)
        return colors.dim(line) if dim else line

    lines = [colors.dim(fmt(headers))]
    for row in rows:
        lines.append(fmt(row))
    return lines


# ---------------------------------------------------------------------------
# Access-log report
# ---------------------------------------------------------------------------

def render_access(data: Dict, top_n: int) -> str:
    """Build the full access-log report text from an analyser result dict."""
    out: List[str] = []
    out.append(_header("HTTP ACCESS LOG REPORT"))

    span = data["time_span"]
    out.append(_kv("Lines read", str(data["files_lines"])))
    out.append(_kv("Parsed requests", str(data["parsed"])))
    out.append(_kv("Unparsed lines", str(data["unparsed"])))
    if data.get("skipped_since"):
        out.append(_kv("Skipped (--since)", str(data["skipped_since"])))
    out.append(_kv("Unique client IPs", str(data["unique_ips"])))
    out.append(_kv("Total bytes sent", _human_bytes(data["total_bytes"])))
    if span["first"] or span["last"]:
        out.append(_kv("Time span", f"{span['first']}  ->  {span['last']}"))
    peak = data["peak_minute"]
    if peak["count"]:
        out.append(
            _kv("Peak req/min", f"{peak['count']} at {peak['minute']}")
        )
    out.append("")

    # Status-code breakdown.
    out.append(_header("Status codes"))
    sc = data["status_classes"]
    order = ["2xx", "3xx", "4xx", "5xx", "1xx", "other"]
    rows = []
    for key in order:
        if key in sc:
            label = key
            count = sc[key]
            # Colour the families by severity.
            if key == "5xx":
                label = colors.red(key)
            elif key == "4xx":
                label = colors.yellow(key)
            elif key == "2xx":
                label = colors.green(key)
            rows.append((label, str(count)))
    out += _table(rows, ["Class", "Count"], ["l", "r"])
    out.append("")

    # Top IPs.
    out.append(_header(f"Top {top_n} client IPs"))
    out += _table(
        [(ip, str(n)) for ip, n in data["top_ips"]],
        ["IP", "Requests"],
        ["l", "r"],
    )
    out.append("")

    # Top paths.
    out.append(_header(f"Top {top_n} paths"))
    out += _table(
        [(_truncate(p, 60), str(n)) for p, n in data["top_paths"]],
        ["Path", "Hits"],
        ["l", "r"],
    )
    out.append("")

    # Top user agents.
    out.append(_header(f"Top {top_n} user-agents"))
    out += _table(
        [(_truncate(a, 60), str(n)) for a, n in data["top_agents"]],
        ["User-Agent", "Hits"],
        ["l", "r"],
    )
    out.append("")

    # Biggest responses.
    out.append(_header(f"Biggest {top_n} responses"))
    out += _table(
        [
            (_human_bytes(b["size"]), str(b["status"]), b["ip"], _truncate(b["path"], 50))
            for b in data["biggest_responses"]
        ],
        ["Size", "Status", "IP", "Path"],
        ["r", "r", "l", "l"],
    )
    out.append("")

    # Suspicious requests - the security heart of the report.
    susp = data["suspicious"]
    title = f"Suspicious requests ({susp['total']})"
    out.append(_header(title))
    if susp["total"] == 0:
        out.append(colors.green("  No suspicious requests detected."))
    else:
        out.append(colors.bold("  By category:"))
        for cat, n in susp["by_category"]:
            label = _CATEGORY_LABELS.get(cat, cat)
            out.append(_kv("  " + label, colors.red(str(n))))
        out.append("")
        out.append(colors.bold("  Offending IPs:"))
        out += _table(
            [(ip, str(n)) for ip, n in susp["by_ip"]],
            ["IP", "Flags"],
            ["l", "r"],
        )
        out.append("")
        out.append(colors.bold("  Sample flagged requests:"))
        out += _table(
            [
                (
                    s["ip"],
                    s["method"],
                    _truncate(s["path"], 44),
                    ",".join(s["categories"]),
                )
                for s in susp["samples"]
            ],
            ["IP", "Method", "Path", "Why"],
            ["l", "l", "l", "l"],
        )
    out.append("")

    out.append(_risk_banner(data["risk"]))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Auth-log report
# ---------------------------------------------------------------------------

def render_auth(data: Dict, top_n: int) -> str:
    """Build the full auth-log report text from an analyser result dict."""
    out: List[str] = []
    out.append(_header("SSH AUTH LOG REPORT"))

    span = data["time_span"]
    out.append(_kv("Lines read", str(data["files_lines"])))
    out.append(_kv("Parsed events", str(data["parsed"])))
    out.append(_kv("Unparsed lines", str(data["unparsed"])))
    if data.get("skipped_since"):
        out.append(_kv("Skipped (--since)", str(data["skipped_since"])))
    out.append(_kv("Failed logins", colors.red(str(data["failed_logins"]))))
    out.append(_kv("Accepted logins", colors.green(str(data["accepted_logins"]))))
    if span["first"] or span["last"]:
        out.append(_kv("Time span", f"{span['first']}  ->  {span['last']}"))
    out.append("")

    # Brute-force detections.
    bf = data["bruteforce"]
    out.append(
        _header(
            f"Brute-force suspects "
            f"(>= {bf['threshold']} fails / {bf['window_minutes']} min)"
        )
    )
    if not bf["hits"]:
        out.append(colors.green("  No brute-force activity detected."))
    else:
        out += _table(
            [
                (
                    colors.red(h["ip"]),
                    str(h["failed_count"]),
                    str(h["peak_in_window"]),
                    # A private-source attack is unusual and worth flagging.
                    colors.yellow(h.get("scope", "other"))
                    if h.get("scope") == "private"
                    else h.get("scope", "other"),
                    _truncate(",".join(h["users_tried"]), 36),
                )
                for h in bf["hits"]
            ],
            ["IP", "Fails", "Peak/win", "Scope", "Users tried"],
            ["l", "r", "r", "l", "l"],
        )
        if any(h.get("scope") == "private" for h in bf["hits"]):
            out.append("")
            out.append(
                colors.yellow(
                    "  Note: one or more attacks originate from a PRIVATE "
                    "address - possible lateral movement / internal host."
                )
            )
    out.append("")

    # Top attacking IPs.
    out.append(_header(f"Top {top_n} attacking IPs"))
    out += _table(
        [(ip, str(n)) for ip, n in data["top_attacking_ips"]],
        ["IP", "Failures"],
        ["l", "r"],
    )
    out.append("")

    # Invalid users tried.
    out.append(_header(f"Top {top_n} invalid users tried"))
    out += _table(
        [(u, str(n)) for u, n in data["top_invalid_users"]],
        ["Username", "Attempts"],
        ["l", "r"],
    )
    out.append("")

    # Accepted logins.
    out.append(_header("Accepted logins"))
    if not data["accepted_users"]:
        out.append("  (none)")
    else:
        out += _table(
            [(u, str(n)) for u, n in data["accepted_users"]],
            ["Username", "Logins"],
            ["l", "r"],
        )
        out.append("")
        out.append(colors.bold("  From IPs:"))
        out += _table(
            [(ip, str(n)) for ip, n in data["accepted_ips"]],
            ["IP", "Logins"],
            ["l", "r"],
        )
    out.append("")

    out.append(_risk_banner(data["risk"]))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _truncate(text: str, length: int) -> str:
    """Shorten ``text`` to ``length`` chars with an ellipsis if needed."""
    text = text or ""
    if len(text) <= length:
        return text
    return text[: length - 1] + "…"


def _risk_banner(risk: str) -> str:
    """Render the final colour-coded risk summary line."""
    style = _RISK_STYLE.get(risk, colors.yellow)
    label = style(colors.bold(f" RISK: {risk} "))
    return _header("Risk summary") + "\n  " + label
