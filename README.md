English | [Русский](README.ru.md)

# logwatch

A zero-dependency **log analysis & security-reporting CLI** written in pure
Python (standard library only). Point it at NGINX/Apache access logs or Linux
`sshd` auth logs and it produces a clear, colour-coded, sectioned security/ops
report — top talkers, status-code health, **suspicious-request detection**
(path traversal, SQLi, scanner probes, …) and **SSH brute-force detection** —
plus machine-readable `--json`, shareable **HTML / Markdown reports**, a
known-good **allow-list**, and a tunable, automation-friendly **exit code**.

It is a single, self-contained package. No `pip install` of anything. Drop it
on any box with Python 3.10+ and run it.

```text
$ python -m logwatch samples/access.log
HTTP ACCESS LOG REPORT
======================
  Lines read             42
  Parsed requests        42
  Unique client IPs      9
  Total bytes sent       5.2 MB
  Peak req/min           12 at 2024-10-10 13:55
  ...
Suspicious requests (9)
=======================
  By category:
    Scanner / recon path  8
    SQL injection pattern 3
    Path traversal (../)  2
    Unusual HTTP method   2
  ...
Risk summary
============
   RISK: MEDIUM
```

---

## Why this exists

When you SSH into a box after an incident, the first thing you do is `grep`,
`awk` and `sort | uniq -c` your way through `access.log` and `auth.log`. This
tool packages those reflexes into one command, adds security heuristics on top,
and works the same everywhere because it has **no dependencies**. It is a
portfolio piece aimed at networking / security / DevOps work.

## Features

- **Two log formats, auto-detected:**
  - NGINX / Apache **combined access logs**
  - Linux **`sshd` auth logs** (`/var/log/auth.log`)
- **Access-log report:** total requests, unique IPs, top IPs / paths /
  user-agents, status-code breakdown (2xx/3xx/4xx/5xx), biggest responses,
  total bytes served, and **peak requests-per-minute**.
- **Suspicious-request detection** (regex heuristics), each flagged with the
  offending IP:
  - path traversal (`../`, encoded variants)
  - SQL-injection-ish payloads (`UNION SELECT`, `OR 1=1`, `; DROP TABLE`, …)
  - cross-site-scripting probes (`<script>`, `onerror=`, …)
  - common scanner / recon paths (`/wp-admin`, `/.env`, `/phpmyadmin`,
    `/.git/`, `/cgi-bin/`, …)
  - sensitive-file probes (`/.env`, `/.git/config`, `/wp-config.php`,
    `/.aws/credentials`, `/id_rsa`, `/.ssh/`, `/.htpasswd`, `/server-status`,
    `/phpinfo.php`, `/.DS_Store`, and `.sql`/`.bak`/`.old` dumps)
  - oversized query strings
  - unusual / disallowed HTTP methods
- **Auth-log report:** failed vs accepted logins, **brute-force detection**
  (IPs over a failure threshold inside a sliding time window), invalid users
  tried, top attacking IPs, and an accepted-logins summary.
- **Allow-list** (`--allow` / `--allow-file`): name your own known-good IPs and
  CIDR ranges (the office egress, a monitoring probe, a CI runner) and their
  detections are suppressed and counted separately, so real attacks stand out.
- **Shareable reports:** `--html report.html` writes a clean, self-contained
  HTML file (inline CSS, no JavaScript, dark-mode aware) you can email or attach
  to a ticket; `--md report.md` writes GitHub-flavoured Markdown for issues,
  wikis or a CI job summary.
- **`--json`** output for piping into other tools.
- **Tunable risk-based exit code** (`--fail-on low|medium|high`) so it works as
  a cron/CI gate (see below).
- **`.gz` support** (detected by magic bytes, not just the extension),
  **multiple files**, and **stdin** (`-`). Corrupt/truncated files and garbage
  lines are warned about and skipped, never crash the run.

## Requirements

- Python **3.10+**
- Nothing else. `requirements.txt` is intentionally empty.

## Install / run

There is nothing to install. Clone the repo and run the package:

```bash
python -m logwatch samples/access.log
python -m logwatch --format auth samples/auth.log
```

## Usage

```text
python -m logwatch [options] LOGFILE [LOGFILE ...]

positional arguments:
  LOGFILE               one or more log files (.gz supported); use '-' for stdin

options:
  --format {auto,access,auth}
                        log format; 'auto' sniffs the content (default: auto)
  --top N               show the top N entries in each ranked section (default: 10)
  --since WHEN          ignore entries before this time
                        (e.g. '2024-10-10' or '2024-10-10 13:00:00')
  --threshold N         auth: failed logins within the window to flag a
                        brute-force IP (default: 5)
  --window MIN          auth: brute-force sliding window in minutes (default: 5)
  --max-query-len N     access: query-string length over which a request is
                        suspicious (default: 512)
  --allow IP/CIDR       treat this IP or CIDR as known-good and suppress its
                        detections; repeatable
  --allow-file PATH     read more allow-list entries (one IP/CIDR per line,
                        '#' comments allowed) from a file
  --json                emit machine-readable JSON instead of the text report
  --html FILE           also write a self-contained HTML report to FILE
  --md FILE             also write a Markdown report to FILE
  --fail-on {low,medium,high}
                        minimum risk level that makes the exit code non-zero,
                        for CI gates (default: medium)
  --color / --no-color  force or disable coloured output
  --version             show the version and exit
```

### Examples

```bash
# Auto-detect format and print a coloured report
python -m logwatch samples/access.log

# Force the auth parser, tighten the brute-force rule to 10 fails / 2 min
python -m logwatch --format auth --threshold 10 --window 2 samples/auth.log

# Analyse a rotated, compressed log and emit JSON, top-5 only
python -m logwatch --json --top 5 samples/access.log.gz

# Suppress your own monitoring / office IPs so real attacks stand out
python -m logwatch --allow 10.0.0.0/8 --allow 198.51.100.7 samples/access.log

# Keep known-good sources in a file (one IP/CIDR per line, # comments allowed)
python -m logwatch --allow-file allow.txt /var/log/auth.log

# Write a shareable HTML and Markdown report alongside the terminal output
python -m logwatch --html report.html --md report.md samples/access.log

# Stream from stdin (e.g. live tail or a remote box)
ssh server 'cat /var/log/auth.log' | python -m logwatch --format auth -

# Only fail a CI step on HIGH risk; MEDIUM is reported but the step passes
python -m logwatch --fail-on high --format auth /var/log/auth.log
```

## Exit codes

logwatch is designed to drop into a cron job or CI step:

| Code | Meaning                                                                 |
|------|------------------------------------------------------------------------|
| `0`  | Report produced; risk **below** the `--fail-on` threshold.             |
| `2`  | Report produced; risk **met or exceeded** `--fail-on` (default MEDIUM).|
| `1`  | Usage / input error (bad `--since`, no readable lines, …).             |

`--fail-on` controls how sensitive the gate is: `--fail-on low` fails on any
detection, `--fail-on high` fails only on a serious one. The default is
`medium`.

```bash
# Fail a pipeline loudly when an attack is visible in today's logs
python -m logwatch --format auth /var/log/auth.log || echo "review the logs!"
```

## Allow-list (known-good sources)

Real logs are full of *your own* infrastructure: the office egress IP, an
uptime probe, a CI runner, a partner's API client. Those hosts trip the
scanner / oversized-query heuristics constantly (health checks, big exports,
pings) and bury genuine attacks in the noise.

`--allow` and `--allow-file` let you name those sources once. Each entry is a
single IP (`198.51.100.7`) or a CIDR range (`10.0.0.0/8`), IPv4 or IPv6:

- Allow-listed sources are **still counted** in the traffic statistics (this is
  not a filter that hides them) — they are only excluded from the security
  detections (suspicious requests, brute-force, top-attacking-IPs).
- The number of suppressed detections is reported separately, so you can see
  how much was filtered.
- Unparseable entries are skipped with a warning; a missing `--allow-file` is
  warned about, not fatal.

```bash
# allow.txt
# our monitoring and CI
198.51.100.7
10.0.0.0/8        # entire internal range
2001:db8:42::/48  # IPv6 office range
```

## Detections explained

### Access logs

| Category            | What triggers it                                                   |
|---------------------|--------------------------------------------------------------------|
| `path_traversal`    | `../`, `..\`, or percent-encoded variants in the path/query.       |
| `sqli`              | `UNION SELECT`, `OR 1=1`, `' OR '1'='1`, `sleep()`, `; DROP TABLE`, `information_schema`, … |
| `xss`               | `<script`, `javascript:`, `onerror=`, `onload=` in the URL.        |
| `scanner_path`      | Requests to known recon paths (`/wp-admin`, `/.env`, `/phpmyadmin`, `/.git/`, `/cgi-bin/`, `/actuator`, …). |
| `sensitive_file`    | Probes for secrets/internals: `/.env`, `/.git/config`, `/wp-config.php`, `/.aws/credentials`, `/id_rsa`, `/.ssh/`, `/.htpasswd`, `/server-status`, `/phpinfo.php`, `/.DS_Store`, and config/db dumps (`.sql`, `.bak`, `.old`, …). A **served** (2xx) sensitive file escalates the run to HIGH risk. |
| `oversized_query`   | Query string longer than `--max-query-len` (default 512 chars).    |
| `bad_method`        | HTTP method outside the normal `GET/POST/HEAD/PUT/DELETE/PATCH/OPTIONS` set. |

Paths are inspected both as logged **and** URL-decoded once, so payloads hidden
behind `%2e%2e%2f`-style encoding are still caught. A single request can match
several categories at once.

### Auth logs

**Brute-force detection** groups failed/invalid login events by source IP,
sorts them by time, and slides a `--window`-minute window across them. If the
number of failures inside the window ever reaches `--threshold` (or the IP's
total failures do), the IP is reported together with the distinct usernames it
tried. Accepted logins are never counted as attacks. Lines without a usable
timestamp still count toward the total, so a missing clock never hides an
attacker.

### Risk summary

A deliberately simple, explainable label (`LOW` / `MEDIUM` / `HIGH`) is printed
at the end and drives the exit code (via `--fail-on`). It is based on the volume
and spread of detections — not a black-box score — so you can reason about it.

## No GeoIP / ASN attribution (by design)

logwatch ships with **no GeoIP/ASN database and makes no network calls** — that
is what keeps it zero-dependency, offline-safe and fast. Consequently it does
**not** tell you which country, network or organisation an IP belongs to. Every
report repeats this disclaimer near its IP tables. To attribute an address,
look it up yourself, e.g.:

```bash
whois 185.220.101.4          # RDAP/whois: owner, ASN, abuse contact
```

…or feed the JSON output into your own threat-intel enrichment.

## Project layout

```
logwatch/
├── logwatch/                 # the runnable package
│   ├── __init__.py
│   ├── __main__.py           # enables `python -m logwatch`
│   ├── cli.py                # argparse, file/gzip/stdin reading, dispatch, exports
│   ├── parsers.py            # access-log & sshd line parsers (pure functions)
│   ├── detectors.py          # suspicious-request + brute-force + allow-list logic
│   ├── analyzers.py          # streaming aggregators -> summary dicts
│   ├── report.py             # human-readable, coloured terminal report
│   ├── exporters.py          # self-contained HTML + Markdown report builders
│   └── colors.py             # tiny ANSI helper (TTY/NO_COLOR aware)
├── samples/                  # synthetic logs that work out of the box
│   ├── access.log            # normal traffic + traversal/SQLi/scanner lines
│   ├── access.log.gz         # the same, gzip-compressed (demonstrates .gz)
│   └── auth.log              # normal logins + an SSH brute-force burst
├── tests/                    # stdlib unittest suite (no network / heavy I/O)
│   ├── test_parsers.py
│   ├── test_detectors.py
│   ├── test_analyzers.py
│   ├── test_allowlist.py     # allow-list + risk-rank + analyser integration
│   ├── test_exporters.py     # HTML/Markdown export (well-formedness, escaping)
│   └── test_cli.py
├── README.md                 # this file (English)
├── README.ru.md              # Russian translation
├── requirements.txt          # intentionally empty (zero deps)
└── .gitignore
```

The design keeps the layers cleanly separated: **parsers** say *what happened*,
**detectors** say *whether it is suspicious*, **analyzers** aggregate, and
**report** / **exporters** render. Every layer except `cli` is pure (no I/O),
which is what makes the test suite fast and deterministic.

## Running the tests

```bash
# From the project root
python -m unittest discover -s tests -v

# Compile-check every source file
python -m py_compile logwatch/*.py tests/*.py
```

The suite (100 tests) covers the parsers, every detector category, the
brute-force window logic, the allow-list (IP/CIDR/IPv6, suppression in both
analysers), the aggregators, format auto-detection, the HTML/Markdown exporters
(well-formedness and HTML-escaping of hostile fields), and the CLI end-to-end
(including gzip input, corrupt-gzip recovery, JSON output, the allow-list flags
and the `--fail-on` exit code).

## Ethics & scope

**Only analyse logs you own or are explicitly authorised to inspect.** This
tool is for defending your own systems — reading your own access/auth logs to
spot attacks and operational problems. The synthetic logs in `samples/` use
documentation/reserved IP ranges (`203.0.113.0/24`, `198.51.100.0/24`,
`192.0.2.0/24`) and contain no real personal data. Do not point logwatch at
infrastructure you do not run, and treat any IPs/usernames in real logs as
sensitive: never paste production logs into shared issues or chats.

## License

Released into the public domain / MIT-style — use it freely. Attribution
appreciated but not required.
