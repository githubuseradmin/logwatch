"""Line parsers for the supported log formats.

Two formats are understood:

* **access** - NGINX / Apache "combined" access logs.
* **auth**   - Linux ``sshd`` authentication logs (``/var/log/auth.log``).

Each parser turns a single raw log line into a small, typed record
(:class:`AccessEntry` / :class:`AuthEvent`) or returns ``None`` when the line
does not match (blank lines, unrelated daemons, malformed rows). Returning
``None`` rather than raising keeps the analysers simple: they just skip what
they cannot understand and count it as "unparsed".

The parsers are pure functions over strings - no I/O - which makes them trivial
to unit test against fixture lines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Access logs (NGINX / Apache combined format)
# ---------------------------------------------------------------------------
#
# A canonical combined line looks like:
#
#   203.0.113.5 - - [10/Oct/2024:13:55:36 +0000] "GET /index.html HTTP/1.1" \
#       200 2326 "https://ref.example/" "Mozilla/5.0 (...)"
#
# Field order: remote_addr - remote_user [time_local] "request" status \
#              body_bytes_sent "http_referer" "http_user_agent"
#
# The request token is itself "METHOD PATH PROTOCOL"; we split it afterwards so
# that weird/garbage requests (which attackers love to send) do not break the
# whole line match.

_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)'                     # remote address (IP or host)
    r'\s+\S+\s+(?P<user>\S+)'           # ident (ignored) + remote user
    r'\s+\[(?P<time>[^\]]+)\]'          # [time_local]
    r'\s+"(?P<request>[^"]*)"'          # "METHOD PATH PROTO"
    r'\s+(?P<status>\d{3}|-)'           # status code
    r'\s+(?P<size>\d+|-)'               # response size in bytes
    r'(?:\s+"(?P<referer>[^"]*)")?'     # optional "referer"
    r'(?:\s+"(?P<agent>[^"]*)")?'       # optional "user-agent"
)

# Strftime pattern for the access-log timestamp, e.g. 10/Oct/2024:13:55:36 +0000
_ACCESS_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


@dataclass
class AccessEntry:
    """A single parsed HTTP access-log line."""

    ip: str
    user: str
    time: Optional[datetime]
    method: str
    path: str
    protocol: str
    status: int
    size: int
    referer: str
    user_agent: str
    raw: str = field(repr=False, default="")

    @property
    def status_class(self) -> str:
        """Return the status family as a string: ``2xx``/``3xx``/``4xx``/``5xx``.

        Anything outside 100-599 (including the placeholder ``0`` used when the
        log wrote ``-``) is bucketed as ``"other"`` so it never silently
        disappears from the breakdown.
        """
        if 100 <= self.status < 200:
            return "1xx"
        if 200 <= self.status < 300:
            return "2xx"
        if 300 <= self.status < 400:
            return "3xx"
        if 400 <= self.status < 500:
            return "4xx"
        if 500 <= self.status < 600:
            return "5xx"
        return "other"


def parse_access_line(line: str) -> Optional[AccessEntry]:
    """Parse one combined-format access-log line into an :class:`AccessEntry`.

    Returns ``None`` if the line does not look like an access-log row. Timestamp
    parsing is tolerant: an unrecognised date yields ``time=None`` rather than a
    failed parse, because traffic counts are still useful without it.
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None

    match = _ACCESS_RE.match(line)
    if not match:
        return None

    g = match.groupdict()

    # Split the "request" token into method / path / protocol. Attackers send
    # malformed request lines on purpose, so we cope with 0-3 tokens.
    request = g.get("request") or ""
    parts = request.split(" ")
    method = parts[0] if len(parts) >= 1 and parts[0] else "-"
    path = parts[1] if len(parts) >= 2 else "-"
    protocol = parts[2] if len(parts) >= 3 else "-"

    # Status / size may be "-"; normalise to integers (0 == unknown).
    status_raw = g.get("status") or "-"
    status = int(status_raw) if status_raw.isdigit() else 0
    size_raw = g.get("size") or "-"
    size = int(size_raw) if size_raw.isdigit() else 0

    # Timestamp is best-effort: keep the row even if the date is unusual.
    when: Optional[datetime] = None
    raw_time = g.get("time") or ""
    try:
        when = datetime.strptime(raw_time, _ACCESS_TIME_FMT)
    except ValueError:
        when = None

    return AccessEntry(
        ip=g.get("ip") or "-",
        user=g.get("user") or "-",
        time=when,
        method=method,
        path=path,
        protocol=protocol,
        status=status,
        size=size,
        referer=g.get("referer") or "",
        user_agent=g.get("agent") or "",
        raw=line,
    )


# ---------------------------------------------------------------------------
# Linux auth logs (sshd)
# ---------------------------------------------------------------------------
#
# Typical syslog-style sshd lines (note: classic syslog has no year):
#
#   Jun 24 09:12:01 host sshd[1123]: Failed password for invalid user admin \
#       from 192.0.2.10 port 50344 ssh2
#   Jun 24 09:12:30 host sshd[1130]: Accepted password for deploy \
#       from 198.51.100.7 port 51001 ssh2
#   Jun 24 09:12:05 host sshd[1124]: Invalid user oracle from 192.0.2.10
#
# We extract: timestamp, event kind, the attempted username (if any) and the
# source IP. ``invalid`` marks whether the username was a known account.

_SYSLOG_PREFIX = (
    r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:\[\d+\])?:\s+'
)

# "Failed password for [invalid user ]<user> from <ip> port <n> ssh2"
_AUTH_FAILED_RE = re.compile(
    _SYSLOG_PREFIX
    + r'Failed password for (?P<invalid>invalid user )?(?P<user>\S+)\s+'
    + r'from (?P<ip>\S+)'
)

# "Accepted password|publickey for <user> from <ip> port <n> ssh2"
_AUTH_ACCEPTED_RE = re.compile(
    _SYSLOG_PREFIX
    + r'Accepted (?P<method>\w+) for (?P<user>\S+)\s+from (?P<ip>\S+)'
)

# "Invalid user <user> from <ip>" (sometimes logged separately from the Failed line)
_AUTH_INVALID_RE = re.compile(
    _SYSLOG_PREFIX + r'Invalid user (?P<user>\S+)\s+from (?P<ip>\S+)'
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass
class AuthEvent:
    """A single parsed sshd authentication event."""

    time: Optional[datetime]
    kind: str          # "failed" | "accepted" | "invalid"
    user: str
    ip: str
    invalid_user: bool  # True if the attempted account does not exist
    method: str         # auth method for accepted logins ("password"/"publickey")
    raw: str = field(repr=False, default="")


def _syslog_time(month: str, day: str, hhmmss: str, assume_year: Optional[int]) -> Optional[datetime]:
    """Build a ``datetime`` from headerless syslog fields.

    Classic syslog lines omit the year, so we default to the supplied
    ``assume_year`` (typically "now"). Returns ``None`` on any malformed field
    rather than raising - timing is a nice-to-have, not a hard requirement.
    """
    mon = _MONTHS.get(month)
    if mon is None:
        return None
    if assume_year is None:
        assume_year = datetime.now().year
    try:
        hh, mm, ss = (int(p) for p in hhmmss.split(":"))
        return datetime(assume_year, mon, int(day), hh, mm, ss, tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def parse_auth_line(line: str, assume_year: Optional[int] = None) -> Optional[AuthEvent]:
    """Parse one sshd auth-log line into an :class:`AuthEvent`.

    Recognises failed passwords, accepted logins and explicit "Invalid user"
    notices. Any other line (sudo, cron, systemd, etc.) returns ``None``.

    :param assume_year: year to stamp on the (year-less) syslog timestamp.
    """
    line = line.rstrip("\n")
    if not line.strip() or "sshd" not in line:
        return None

    m = _AUTH_FAILED_RE.match(line)
    if m:
        g = m.groupdict()
        return AuthEvent(
            time=_syslog_time(g["month"], g["day"], g["time"], assume_year),
            kind="failed",
            user=g["user"],
            ip=g["ip"],
            invalid_user=bool(g.get("invalid")),
            method="password",
            raw=line,
        )

    m = _AUTH_ACCEPTED_RE.match(line)
    if m:
        g = m.groupdict()
        return AuthEvent(
            time=_syslog_time(g["month"], g["day"], g["time"], assume_year),
            kind="accepted",
            user=g["user"],
            ip=g["ip"],
            invalid_user=False,
            method=g.get("method", "password"),
            raw=line,
        )

    m = _AUTH_INVALID_RE.match(line)
    if m:
        g = m.groupdict()
        return AuthEvent(
            time=_syslog_time(g["month"], g["day"], g["time"], assume_year),
            kind="invalid",
            user=g["user"],
            ip=g["ip"],
            invalid_user=True,
            method="password",
            raw=line,
        )

    return None
