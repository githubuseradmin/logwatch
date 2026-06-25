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
from datetime import datetime, timezone
from typing import Iterable, Iterator, List, Optional, TextIO

from . import __version__, colors
from .analyzers import AccessAnalyzer, AuthAnalyzer
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
            "  cat /var/log/auth.log | python -m logwatch --format auth -\n\n"
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
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of the text report",
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

    Files that cannot be opened produce a warning on stderr and are skipped, so
    one bad path does not abort an otherwise useful multi-file run.
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
            for line in stream:
                yield line
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


def main(argv: Optional[List[str]] = None) -> int:
    """Program entry point. Returns a shell exit code.

    Exit codes:
      * 0  - report produced, nothing suspicious (risk LOW)
      * 1  - usage / input error (bad --since, no readable lines)
      * 2  - report produced, but a MEDIUM or HIGH risk was detected

    The non-zero "risk" code is deliberate: it lets logwatch be dropped into a
    cron job or CI gate that should fail loudly when an attack is visible.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    colors.configure(args.color)

    try:
        since = _parse_since(args.since)
    except ValueError as exc:
        print(colors.red(f"error: {exc}"), file=sys.stderr)
        return 1

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

    # Map the textual risk label to an exit code for automation.
    risk = data.get("risk", "LOW")
    return 2 if risk in ("MEDIUM", "HIGH") else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
