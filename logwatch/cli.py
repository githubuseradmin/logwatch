"""Command-line interface: argument parsing, file reading, dispatch, output.

This is the only module that touches the outside world (argv, the filesystem,
stdout). It wires together the pure pieces:

    raw lines --> analyzer.feed_line() --> analyzer.result() --> report / JSON

Supported inputs: one or more files, plain or gzip-compressed (``.gz`` is
detected by magic bytes, not just the extension), plus ``-`` for stdin. The log
format is auto-detected from the first lines, or forced with ``--format``.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import sys
import zlib
from datetime import datetime, timezone
from typing import Iterable, Iterator, List, Optional, TextIO

from . import __version__, colors
from .analyzers import AccessAnalyzer, AuthAnalyzer
from .detectors import AllowList, risk_rank
from .exporters import render_html, render_markdown
from .parsers import parse_access_line, parse_auth_line
from .report import render_access, render_auth

# Gzip files start with these two magic bytes regardless of extension.
_GZIP_MAGIC = b"\x1f\x8b"

# Accepted --since input formats (most specific first).
_SINCE_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
)


def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser. Separated out so tests can introspect it."""
    parser = argparse.ArgumentParser(
        prog="logwatch",
        description=(
            "Zero-dependency log analysis & security reporting for "
            "NGINX/Apache access logs and Linux sshd auth logs."
        ),
        epilog=(
            "Examples:\n"
            "  python -m logwatch samples/access.log\n"
            "  python -m logwatch --format auth samples/auth.log\n"
            "  python -m logwatch --json --top 5 samples/access.log.gz\n"
            "  python -m logwatch --html report.html --md report.md samples/access.log\n"
            "  python -m logwatch --allow 10.0.0.0/8 --fail-on high /var/log/auth.log\n"
            "  cat /var/log/auth.log | python -m logwatch --format auth -\n\n"
            "Note: logwatch does no GeoIP/ASN/whois lookups and makes no network\n"
            "calls; resolve IP ownership yourself (e.g. 'whois <ip>').\n\n"
            "Ethics: only analyse logs you own or are explicitly authorised "
            "to inspect."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "files",
        nargs="+",
        metavar="LOGFILE",
        help="one or more log files (.gz supported); use '-' for stdin",
    )
    parser.add_argument(
        "--format",
        choices=("auto", "access", "auth"),
        default="auto",
        help="log format; 'auto' sniffs the content (default: auto)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="show the top N entries in each ranked section (default: 10)",
    )
    parser.add_argument(
        "--since",
        metavar="WHEN",
        help="ignore entries before this time "
        "(e.g. '2024-10-10' or '2024-10-10 13:00:00')",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        metavar="N",
        help="auth: failed logins within the window to flag a brute-force IP "
        "(default: 5)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=5,
        metavar="MIN",
        help="auth: brute-force sliding window in minutes (default: 5)",
    )
    parser.add_argument(
        "--max-query-len",
        type=int,
        default=512,
        metavar="N",
        help="access: query-string length over which a request is suspicious "
        "(default: 512)",
    )
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="IP/CIDR",
        help="treat this IP or CIDR range as known-good and suppress its "
        "detections; repeatable (e.g. --allow 10.0.0.0/8 --allow 198.51.100.7)",
    )
    parser.add_argument(
        "--allow-file",
        metavar="PATH",
        help="read additional allow-list entries (one IP/CIDR per line, '#' "
        "comments allowed) from a file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of the text report",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        help="also write a self-contained HTML report to FILE",
    )
    parser.add_argument(
        "--md",
        metavar="FILE",
        help="also write a Markdown report to FILE",
    )
    parser.add_argument(
        "--fail-on",
        choices=("low", "medium", "high"),
        default="medium",
        help="minimum risk level that makes the exit code non-zero, for CI "
        "gates (default: medium)",
    )
    color = parser.add_mutually_exclusive_group()
    color.add_argument(
        "--color",
        dest="color",
        action="store_const",
        const="always",
        help="force coloured output even when not a TTY",
    )
    color.add_argument(
        "--no-color",
        dest="color",
        action="store_const",
        const="never",
        help="disable coloured output",
    )
    parser.set_defaults(color="auto")
    parser.add_argument(
        "--version",
        action="version",
        version=f"logwatch {__version__}",
    )
    return parser


def _parse_since(value: Optional[str]) -> Optional[datetime]:
    """Parse a ``--since`` string into a timezone-aware UTC datetime.

    We assume UTC for naive inputs so comparisons against the timezone-aware
    timestamps produced by the parsers never raise. Returns ``None`` for empty
    input and raises :class:`ValueError` for an unrecognised format.
    """
    if not value:
        return None
    for fmt in _SINCE_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"unrecognised --since value: {value!r}")


def _build_allowlist(entries: List[str], allow_file: Optional[str]) -> AllowList:
    """Combine ``--allow`` entries and an optional ``--allow-file`` into one list.

    File reading is tolerant: a missing or unreadable allow-file produces a
    warning on stderr and is skipped rather than aborting the run, matching how
    log files themselves are handled. Malformed entries are surfaced later via
    :attr:`AllowList.bad_entries`.
    """
    items: List[str] = list(entries)
    if allow_file:
        try:
            with open(allow_file, "r", encoding="utf-8", errors="replace") as fh:
                items.extend(fh.read().splitlines())
        except OSError as exc:
            print(
                colors.yellow(f"warning: cannot read --allow-file {allow_file}: {exc}"),
                file=sys.stderr,
            )
    return AllowList(items)


def _open_log(path: str) -> TextIO:
    """Open a log file as a text stream, transparently handling gzip and stdin.

    ``-`` means standard input. Otherwise we peek at the first two bytes to
    decide between gzip and plain text, so a ``.gz`` payload is handled even if
    the file was renamed. Decoding is UTF-8 with ``errors='replace'`` because
    real-world logs frequently contain stray bytes we must not crash on.
    """
    if path == "-":
        # Re-wrap stdin's buffer so we get consistent decoding behaviour.
        return io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")

    # Peek at the first two bytes to decide gzip vs plain, then re-open so the
    # returned stream fully owns its file handle. We let ``gzip.open`` /
    # ``open`` take the path directly so that closing the TextIOWrapper closes
    # the whole chain, including the underlying OS file (no resource leak).
    with open(path, "rb") as probe:
        is_gzip = probe.read(2) == _GZIP_MAGIC

    if is_gzip:
        return gzip.open(path, mode="rt", encoding="utf-8", errors="replace")
    return open(path, mode="rt", encoding="utf-8", errors="replace")


def _iter_lines(paths: List[str]) -> Iterator[str]:
    """Yield every line from every input file in order.

    Robust against bad inputs: a file that cannot be *opened* (missing,
    permission denied) and a file that fails mid-*read* (a truncated or corrupt
    ``.gz`` whose magic bytes looked valid) both produce a warning on stderr and
    are skipped. One bad file therefore never aborts an otherwise useful
    multi-file run - we yield everything we managed to read from it first.
    """
    for path in paths:
        try:
            stream = _open_log(path)
        except OSError as exc:
            print(
                colors.yellow(f"warning: cannot open {path}: {exc}"),
                file=sys.stderr,
            )
            continue
        try:
            # gzip decoding errors surface here during iteration, not at open
            # time, so the read loop itself has to be guarded. The relevant
            # exceptions are gzip.BadGzipFile (an OSError), a truncated-stream
            # EOFError, and zlib.error (which derives straight from Exception,
            # so it must be named explicitly - it is not an OSError).
            try:
                for line in stream:
                    yield line
            except (OSError, EOFError, zlib.error) as exc:
                print(
                    colors.yellow(f"warning: error reading {path}: {exc}"),
                    file=sys.stderr,
                )
        finally:
            # Never close the wrapper around the shared stdin buffer.
            if path != "-":
                stream.close()


def detect_format(lines: Iterable[str], sample_size: int = 200) -> str:
    """Sniff whether a stream is an access log or an auth log.

    We try both parsers on up to ``sample_size`` lines and pick whichever wins
    the most. Ties (and totally empty samples) fall back to ``"access"``,
    since that is the more common ask. This consumes only a prefix of the
    iterator's items when given a list; callers pass a buffered prefix.
    """
    access_hits = 0
    auth_hits = 0
    seen = 0
    for line in lines:
        if seen >= sample_size:
            break
        seen += 1
        if parse_auth_line(line) is not None:
            auth_hits += 1
        elif parse_access_line(line) is not None:
            access_hits += 1
    if auth_hits > access_hits:
        return "auth"
    return "access"


def _write_export(path: str, text: str, label: str) -> bool:
    """Write an export artefact to ``path``; warn and return ``False`` on error."""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError as exc:
        print(colors.yellow(f"warning: cannot write {label} {path}: {exc}"), file=sys.stderr)
        return False
    print(colors.dim(f"wrote {label} report to {path}"), file=sys.stderr)
    return True


def main(argv: Optional[List[str]] = None) -> int:
    """Program entry point. Returns a shell exit code.

    Exit codes:
      * 0  - report produced; risk below the ``--fail-on`` threshold.
      * 1  - usage / input error (bad --since, no readable lines).
      * 2  - report produced, and the run's risk met or exceeded ``--fail-on``.

    The non-zero "risk" code is deliberate: it lets logwatch be dropped into a
    cron job or CI gate that should fail loudly when an attack is visible.
    ``--fail-on`` (low/medium/high) tunes how sensitive that gate is.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    colors.configure(args.color)

    try:
        since = _parse_since(args.since)
    except ValueError as exc:
        print(colors.red(f"error: {exc}"), file=sys.stderr)
        return 1

    # Build the allow-list (known-good IPs/CIDRs) and warn about junk entries.
    allow = _build_allowlist(args.allow, args.allow_file)
    if allow.bad_entries:
        print(
            colors.yellow(
                "warning: ignoring unparseable allow-list entries: "
                + ", ".join(allow.bad_entries)
            ),
            file=sys.stderr,
        )

    # Materialise all lines once. Logs analysed interactively are typically
    # small enough; for very large inputs the user can pre-filter with grep.
    lines = list(_iter_lines(args.files))
    if not lines:
        print(colors.red("error: no readable log lines found"), file=sys.stderr)
        return 1

    # Resolve the format (sniff a prefix when set to auto).
    fmt = args.format
    if fmt == "auto":
        fmt = detect_format(lines)

    if fmt == "auth":
        analyzer = AuthAnalyzer(
            top_n=args.top,
            since=since,
            bf_threshold=args.threshold,
            bf_window=args.window,
            allow=allow,
        )
        for line in lines:
            analyzer.feed_line(line)
        data = analyzer.result()
        rendered = render_auth(data, args.top)
    else:  # access
        analyzer = AccessAnalyzer(
            top_n=args.top,
            since=since,
            max_query_len=args.max_query_len,
            allow=allow,
        )
        for line in lines:
            analyzer.feed_line(line)
        data = analyzer.result()
        rendered = render_access(data, args.top)

    if args.json:
        json.dump(data, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
    else:
        print(rendered)

    # Optional export artefacts. These are written in addition to whatever went
    # to stdout, so you can get a coloured terminal view and a shareable file in
    # one run.
    if args.html:
        _write_export(args.html, render_html(data, args.top), "HTML")
    if args.md:
        _write_export(args.md, render_markdown(data, args.top), "Markdown")

    # Map the textual risk label to an exit code for automation. The run "fails"
    # (exit 2) only when its risk reaches the --fail-on threshold.
    risk = data.get("risk", "LOW")
    threshold = args.fail_on.upper()
    return 2 if risk_rank(risk) >= risk_rank(threshold) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
