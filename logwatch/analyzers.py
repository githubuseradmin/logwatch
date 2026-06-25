"""Aggregators that turn a stream of parsed records into report-ready stats.

The CLI feeds raw log lines into one of these analysers; the analyser owns all
the running counters (``collections.Counter`` everywhere) and the list of
flagged events. When the input is exhausted, :meth:`result` returns a plain
dict that both the terminal renderer and the ``--json`` output consume. Keeping
the aggregation logic here (rather than in the CLI) means the whole pipeline is
unit-testable without touching argv, files or stdout.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from . import detectors
from .parsers import (
    AccessEntry,
    AuthEvent,
    parse_access_line,
    parse_auth_line,
)


# ---------------------------------------------------------------------------
# Access-log analyser
# ---------------------------------------------------------------------------

@dataclass
class AccessAnalyzer:
    """Accumulate statistics and detections over HTTP access-log lines."""

    top_n: int = 10
    since: Optional[datetime] = None
    max_query_len: int = detectors.MAX_QUERY_LEN
    allow: Optional[detectors.AllowList] = None

    # Running counters (created fresh per instance).
    total_lines: int = 0
    parsed: int = 0
    unparsed: int = 0
    skipped_since: int = 0
    suppressed: int = 0  # suspicions hidden because the source IP is allow-listed

    ips: Counter = field(default_factory=Counter)
    paths: Counter = field(default_factory=Counter)
    agents: Counter = field(default_factory=Counter)
    status_classes: Counter = field(default_factory=Counter)
    status_codes: Counter = field(default_factory=Counter)
    methods: Counter = field(default_factory=Counter)
    per_minute: Counter = field(default_factory=Counter)

    total_bytes: int = 0
    biggest: List[AccessEntry] = field(default_factory=list)
    suspicions: List[detectors.Suspicion] = field(default_factory=list)

    # Time span observed in the data.
    first_time: Optional[datetime] = None
    last_time: Optional[datetime] = None

    def feed_line(self, line: str) -> None:
        """Parse and incorporate a single raw access-log line."""
        self.total_lines += 1
        entry = parse_access_line(line)
        if entry is None:
            self.unparsed += 1
            return

        # Honour --since: drop records older than the cutoff (only when we have
        # a usable timestamp; undated rows are always kept).
        if self.since is not None and entry.time is not None and entry.time < self.since:
            self.skipped_since += 1
            return

        self.parsed += 1
        self._accumulate(entry)

    def _accumulate(self, entry: AccessEntry) -> None:
        self.ips[entry.ip] += 1
        self.paths[entry.path] += 1
        if entry.user_agent:
            self.agents[entry.user_agent] += 1
        self.status_classes[entry.status_class] += 1
        self.status_codes[entry.status] += 1
        self.methods[entry.method] += 1
        self.total_bytes += entry.size

        # Track the time span and per-minute request rate (for peak detection).
        if entry.time is not None:
            if self.first_time is None or entry.time < self.first_time:
                self.first_time = entry.time
            if self.last_time is None or entry.time > self.last_time:
                self.last_time = entry.time
            bucket = entry.time.strftime("%Y-%m-%d %H:%M")
            self.per_minute[bucket] += 1

        # Keep a small leaderboard of the largest responses without holding the
        # entire dataset in memory.
        self._consider_biggest(entry)

        # Security heuristics. A request from an allow-listed source is still
        # counted in all the traffic stats above, but never raised as a
        # suspicion - that is the whole point of the allow-list.
        suspicion = detectors.classify_suspicious(entry, max_query_len=self.max_query_len)
        if suspicion is not None:
            if self.allow is not None and self.allow.contains(entry.ip):
                self.suppressed += 1
            else:
                self.suspicions.append(suspicion)

    def _consider_biggest(self, entry: AccessEntry) -> None:
        """Maintain a top-N list of the biggest responses by body size."""
        limit = max(self.top_n, 5)
        if len(self.biggest) < limit:
            self.biggest.append(entry)
            self.biggest.sort(key=lambda e: e.size, reverse=True)
        elif entry.size > self.biggest[-1].size:
            self.biggest[-1] = entry
            self.biggest.sort(key=lambda e: e.size, reverse=True)

    def result(self) -> Dict:
        """Return a JSON-serialisable summary of everything observed."""
        peak_minute, peak_count = ("", 0)
        if self.per_minute:
            peak_minute, peak_count = self.per_minute.most_common(1)[0]

        # Collapse suspicions into per-IP and per-category tallies for the report.
        susp_by_ip: Counter = Counter()
        susp_by_cat: Counter = Counter()
        for s in self.suspicions:
            susp_by_ip[s.ip] += 1
            for c in s.categories:
                susp_by_cat[c] += 1

        return {
            "kind": "access",
            "files_lines": self.total_lines,
            "parsed": self.parsed,
            "unparsed": self.unparsed,
            "skipped_since": self.skipped_since,
            "unique_ips": len(self.ips),
            "total_bytes": self.total_bytes,
            "time_span": {
                "first": self.first_time.isoformat() if self.first_time else None,
                "last": self.last_time.isoformat() if self.last_time else None,
            },
            "top_ips": self.ips.most_common(self.top_n),
            "top_paths": self.paths.most_common(self.top_n),
            "top_agents": self.agents.most_common(self.top_n),
            "methods": self.methods.most_common(),
            "status_classes": dict(sorted(self.status_classes.items())),
            "status_codes": dict(sorted(self.status_codes.items())),
            "peak_minute": {"minute": peak_minute, "count": peak_count},
            "biggest_responses": [
                {
                    "ip": e.ip,
                    "path": e.path,
                    "size": e.size,
                    "status": e.status,
                }
                for e in self.biggest[: self.top_n]
            ],
            "suspicious": {
                "total": len(self.suspicions),
                "suppressed": self.suppressed,
                "by_category": susp_by_cat.most_common(),
                "by_ip": susp_by_ip.most_common(self.top_n),
                "samples": [
                    {
                        "ip": s.ip,
                        "method": s.entry.method,
                        "path": s.entry.path,
                        "status": s.entry.status,
                        "categories": s.categories,
                    }
                    for s in self.suspicions[: self.top_n]
                ],
            },
            "risk": detectors.summarize_risk_access(self.suspicions, self.parsed),
        }


# ---------------------------------------------------------------------------
# Auth-log analyser
# ---------------------------------------------------------------------------

@dataclass
class AuthAnalyzer:
    """Accumulate statistics and detections over sshd auth-log lines."""

    top_n: int = 10
    since: Optional[datetime] = None
    bf_threshold: int = 5
    bf_window: int = 5
    assume_year: Optional[int] = None
    allow: Optional[detectors.AllowList] = None

    total_lines: int = 0
    parsed: int = 0
    unparsed: int = 0
    skipped_since: int = 0
    suppressed: int = 0  # failed/invalid events hidden because the IP is allow-listed

    failed: int = 0
    accepted: int = 0

    failed_ips: Counter = field(default_factory=Counter)
    invalid_users: Counter = field(default_factory=Counter)
    accepted_users: Counter = field(default_factory=Counter)
    accepted_ips: Counter = field(default_factory=Counter)

    events: List[AuthEvent] = field(default_factory=list)

    first_time: Optional[datetime] = None
    last_time: Optional[datetime] = None

    def feed_line(self, line: str) -> None:
        """Parse and incorporate a single raw auth-log line."""
        self.total_lines += 1
        event = parse_auth_line(line, assume_year=self.assume_year)
        if event is None:
            self.unparsed += 1
            return

        if self.since is not None and event.time is not None and event.time < self.since:
            self.skipped_since += 1
            return

        self.parsed += 1
        self._accumulate(event)

    def _accumulate(self, event: AuthEvent) -> None:
        # We keep events for the windowed brute-force pass at the end.
        self.events.append(event)

        if event.time is not None:
            if self.first_time is None or event.time < self.first_time:
                self.first_time = event.time
            if self.last_time is None or event.time > self.last_time:
                self.last_time = event.time

        # An allow-listed source is still parsed and time-spanned, but its
        # failed/invalid attempts are not counted as attack pressure (no entry
        # in failed_ips / invalid_users), so it never appears in the report's
        # "top attacking IPs" or brute-force sections.
        allow_listed = self.allow is not None and self.allow.contains(event.ip)

        if event.kind == "failed":
            self.failed += 1
            if allow_listed:
                self.suppressed += 1
            else:
                self.failed_ips[event.ip] += 1
                if event.invalid_user:
                    self.invalid_users[event.user] += 1
        elif event.kind == "invalid":
            # "Invalid user" notices count toward attack pressure too.
            if allow_listed:
                self.suppressed += 1
            else:
                self.failed_ips[event.ip] += 1
                self.invalid_users[event.user] += 1
        elif event.kind == "accepted":
            self.accepted += 1
            self.accepted_users[event.user] += 1
            self.accepted_ips[event.ip] += 1

    def result(self) -> Dict:
        """Return a JSON-serialisable summary of everything observed."""
        bf_hits = detectors.detect_bruteforce(
            self.events,
            threshold=self.bf_threshold,
            window_minutes=self.bf_window,
            allow=self.allow,
        )

        return {
            "kind": "auth",
            "files_lines": self.total_lines,
            "parsed": self.parsed,
            "unparsed": self.unparsed,
            "skipped_since": self.skipped_since,
            "suppressed": self.suppressed,
            "failed_logins": self.failed,
            "accepted_logins": self.accepted,
            "time_span": {
                "first": self.first_time.isoformat() if self.first_time else None,
                "last": self.last_time.isoformat() if self.last_time else None,
            },
            "top_attacking_ips": self.failed_ips.most_common(self.top_n),
            "top_invalid_users": self.invalid_users.most_common(self.top_n),
            "accepted_users": self.accepted_users.most_common(self.top_n),
            "accepted_ips": self.accepted_ips.most_common(self.top_n),
            "bruteforce": {
                "threshold": self.bf_threshold,
                "window_minutes": self.bf_window,
                "hits": [
                    {
                        "ip": h.ip,
                        "failed_count": h.failed_count,
                        "peak_in_window": h.peak_in_window,
                        "users_tried": h.users_tried,
                        "scope": h.scope,
                    }
                    for h in bf_hits
                ],
            },
            "risk": detectors.summarize_risk_auth(bf_hits, self.failed),
        }
