"""Security heuristics applied on top of the parsed log records.

This module is intentionally separate from parsing: parsers tell you *what
happened*, detectors tell you *whether it is suspicious*. Splitting them keeps
each piece easy to test and lets the detection rules evolve without touching
the line-format code.

Two families of detectors live here:

* :func:`classify_suspicious` - per-request heuristics for HTTP access logs
  (path traversal, SQLi-ish payloads, scanner/recon paths, oversized query
  strings and disallowed HTTP methods).
* :func:`detect_bruteforce` - windowed brute-force detection for sshd auth
  logs (an IP exceeding a failed-login threshold inside a sliding time window).

All thresholds are passed in explicitly (with sensible defaults) so they can be
tuned from the CLI and pinned in tests.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable, List, Optional, Sequence
from urllib.parse import unquote_plus

from .parsers import AccessEntry, AuthEvent


# RFC1918 / loopback / link-local: the "inside the perimeter" ranges. An attack
# from one of these is a very different (and more alarming) story - lateral
# movement, a compromised internal host or an insider - than the constant
# background noise of public internet scanners. We test these explicitly rather
# than relying on ``is_private``, because in modern Python ``is_private`` is
# True for documentation/reserved ranges too (e.g. 203.0.113.0/24), which would
# mislabel them.
_INTERNAL_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def classify_ip(value: str) -> str:
    """Classify a source address as ``private``, ``public`` or ``other``.

    * ``private`` - RFC1918 / loopback / link-local (inside the perimeter).
    * ``public``  - a globally-routable address (a real internet source).
    * ``other``   - anything else: documentation/reserved ranges, multicast,
      or a value that is not an IP at all (a logged hostname, or ``-``).

    Using explicit internal networks plus :attr:`is_global` keeps the labels
    meaningful even for the reserved ranges used by the sample logs.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "other"
    if any(ip in net for net in _INTERNAL_NETS):
        return "private"
    if ip.is_global:
        return "public"
    return "other"

# ---------------------------------------------------------------------------
# HTTP access-log heuristics
# ---------------------------------------------------------------------------

# HTTP methods we consider legitimate for a typical web service. Anything else
# (DEBUG, TRACE, PROPFIND, random garbage from a scanner) is flagged.
ALLOWED_METHODS = frozenset(
    {"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"}
)

# Query strings longer than this are treated as suspicious. Real query strings
# are rarely this long; huge ones usually mean an injection or buffer probe.
MAX_QUERY_LEN = 512

# Path traversal: ../ or ..\ or their percent-encoded variants. We decode the
# path first (see _decode), so the encoded forms are mostly defence in depth.
_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e[/\\]|\.\.%2f|\.\.%5c)", re.IGNORECASE)

# SQL-injection-ish signatures. Deliberately conservative to limit false
# positives: UNION SELECT, boolean tautologies, stacked comments, sleep/benchmark.
_SQLI_RE = re.compile(
    r"("
    r"union(\s|\+|%20|/\*)+select"          # UNION SELECT
    r"|select(\s|\+|%20)+.*(\s|\+|%20)+from" # SELECT ... FROM
    r"|\bor\b\s+1\s*=\s*1"                   # OR 1=1
    r"|'\s*or\s*'1'\s*=\s*'1"                # ' OR '1'='1
    r"|sleep\s*\(\s*\d+\s*\)"                # sleep(5)
    r"|benchmark\s*\("                        # benchmark(...)
    r"|information_schema"                    # schema enumeration
    r"|;\s*drop\s+table"                      # ; DROP TABLE
    r")",
    re.IGNORECASE,
)

# Cross-site-scripting probes in the URL.
_XSS_RE = re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=)", re.IGNORECASE)

# Well-known scanner / recon paths. Requests to these on a host that does not
# serve them are a strong signal of automated probing.
_SCANNER_PATHS = (
    "/wp-admin", "/wp-login.php", "/xmlrpc.php", "/.env", "/.git/",
    "/phpmyadmin", "/pma", "/adminer", "/.aws/credentials", "/config.php",
    "/vendor/phpunit", "/shell", "/cgi-bin/", "/.ssh/", "/server-status",
    "/actuator", "/solr/", "/boaform", "/manager/html", "/.well-known/security",
)


@dataclass
class Suspicion:
    """A single suspicious access request and why it was flagged."""

    entry: AccessEntry
    categories: List[str]  # e.g. ["path_traversal", "scanner_path"]

    @property
    def ip(self) -> str:
        return self.entry.ip


def _decode(value: str) -> str:
    """URL-decode a path/query once so encoded payloads are comparable.

    We decode a single layer (``%2e`` -> ``.``, ``+`` -> space). A single pass
    is enough for the vast majority of real-world probes while avoiding the
    pathological cost of fully recursive decoding.
    """
    try:
        return unquote_plus(value)
    except Exception:
        return value


def classify_suspicious(
    entry: AccessEntry,
    *,
    max_query_len: int = MAX_QUERY_LEN,
) -> Optional[Suspicion]:
    """Return a :class:`Suspicion` if ``entry`` trips any heuristic, else ``None``.

    The full raw path is examined both as-logged and URL-decoded, so payloads
    hidden behind percent-encoding are still caught. Multiple categories can
    fire for a single request (e.g. a scanner path that also contains SQLi).
    """
    categories: List[str] = []

    raw_path = entry.path or ""
    decoded = _decode(raw_path)
    # Compare against both forms to defeat simple encoding evasion.
    haystack = f"{raw_path}\n{decoded}"

    # 1) Path traversal.
    if _TRAVERSAL_RE.search(haystack):
        categories.append("path_traversal")

    # 2) SQL injection signatures.
    if _SQLI_RE.search(haystack):
        categories.append("sqli")

    # 3) Cross-site scripting in the URL.
    if _XSS_RE.search(haystack):
        categories.append("xss")

    # 4) Known scanner / sensitive recon paths (case-insensitive prefix/contains).
    low = decoded.lower()
    if any(sp in low for sp in _SCANNER_PATHS):
        categories.append("scanner_path")

    # 5) Oversized query string (everything after the first '?').
    query = raw_path.split("?", 1)[1] if "?" in raw_path else ""
    if len(query) > max_query_len:
        categories.append("oversized_query")

    # 6) Unusual / disallowed HTTP method.
    if entry.method and entry.method != "-" and entry.method.upper() not in ALLOWED_METHODS:
        categories.append("bad_method")

    if not categories:
        return None
    return Suspicion(entry=entry, categories=categories)


# ---------------------------------------------------------------------------
# sshd brute-force detection
# ---------------------------------------------------------------------------

@dataclass
class BruteForceHit:
    """A source IP that crossed the brute-force threshold."""

    ip: str
    failed_count: int          # total failed attempts from this IP
    peak_in_window: int        # most failures seen inside one sliding window
    users_tried: List[str]     # distinct usernames attempted (capped for display)
    scope: str = "other"       # "public" / "private" / "other" (see classify_ip)


def detect_bruteforce(
    events: Iterable[AuthEvent],
    *,
    threshold: int = 5,
    window_minutes: int = 5,
) -> List[BruteForceHit]:
    """Flag IPs with too many failed sshd logins inside a sliding time window.

    Algorithm: group failed/invalid events by source IP, sort each group by
    time, then slide a ``window_minutes`` window with a deque. If the number of
    failures inside the window ever reaches ``threshold``, the IP is reported.
    Events lacking a timestamp fall back to a pure count check so we never miss
    an attacker just because the clock was unparseable.

    Results are sorted by total failure count, descending (worst first).
    """
    by_ip: dict[str, List[AuthEvent]] = defaultdict(list)
    for ev in events:
        if ev.kind in ("failed", "invalid"):
            by_ip[ev.ip].append(ev)

    window = timedelta(minutes=window_minutes)
    hits: List[BruteForceHit] = []

    for ip, evs in by_ip.items():
        total = len(evs)
        users = []
        seen_users = set()
        for e in evs:
            if e.user not in seen_users:
                seen_users.add(e.user)
                users.append(e.user)

        # Compute the busiest window. If timestamps are present we slide a real
        # time window; otherwise the peak is just the total count.
        timed = sorted((e for e in evs if e.time is not None), key=lambda e: e.time)
        peak = 0
        if timed:
            q: deque = deque()
            for e in timed:
                q.append(e.time)
                while q and (e.time - q[0]) > window:
                    q.popleft()
                peak = max(peak, len(q))
        # Untimed events still count toward the raw total.
        peak = max(peak, total - len(timed))

        if peak >= threshold or total >= threshold:
            hits.append(
                BruteForceHit(
                    ip=ip,
                    failed_count=total,
                    peak_in_window=peak,
                    users_tried=users[:10],  # cap the list for a tidy report
                    scope=classify_ip(ip),
                )
            )

    hits.sort(key=lambda h: h.failed_count, reverse=True)
    return hits


def summarize_risk_access(suspicions: Sequence[Suspicion], total_requests: int) -> str:
    """Return a coarse risk label for an access-log run.

    The label feeds the final "risk summary" section. It is intentionally
    simple and explainable rather than a black-box score.
    """
    if not suspicions:
        return "LOW"
    distinct_ips = len({s.ip for s in suspicions})
    n = len(suspicions)
    if n >= 25 or distinct_ips >= 10:
        return "HIGH"
    if n >= 5:
        return "MEDIUM"
    return "LOW"


def summarize_risk_auth(hits: Sequence[BruteForceHit], total_failed: int) -> str:
    """Return a coarse risk label for an auth-log run."""
    if not hits and total_failed == 0:
        return "LOW"
    if any(h.failed_count >= 50 for h in hits) or len(hits) >= 5:
        return "HIGH"
    if hits:
        return "MEDIUM"
    return "LOW"
