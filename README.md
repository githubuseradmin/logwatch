# logwatch

A zero-dependency **log analysis & security-reporting CLI** written in pure
Python (standard library only). Point it at NGINX/Apache access logs or Linux
`sshd` auth logs and it produces a clear, colour-coded, sectioned security/ops
report — top talkers, status-code health, **suspicious-request detection**
(path traversal, SQLi, scanner probes, …) and **SSH brute-force detection** —
plus a machine-readable `--json` mode and an automation-friendly exit code.

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
Suspicious requests (15)
========================
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
  - oversized query strings
  - unusual / disallowed HTTP methods
- **Auth-log report:** failed vs accepted logins, **brute-force detection**
  (IPs over a failure threshold inside a sliding time window), invalid users
  tried, top attacking IPs, and an accepted-logins summary.
- **`.gz` support** (detected by magic bytes, not just the extension),
  **multiple files**, and **stdin** (`-`).
- Flags: `--top N`, `--since`, `--format`, `--threshold`, `--window`,
  `--max-query-len`, `--json`, `--color/--no-color`.
- **`--json`** output for piping into other tools.
- **Risk-based exit code** so it works as a cron/CI gate (see below).

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
  --json                emit machine-readable JSON instead of the text report
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

# Stream from stdin (e.g. live tail or a remote box)
ssh server 'cat /var/log/auth.log' | python -m logwatch --format auth -

# Only look at events from a given moment onward
python -m logwatch --since '2024-10-10 13:57:00' samples/access.log

# Analyse several files at once
python -m logwatch samples/access.log samples/access.log.gz
```

## Exit codes

logwatch is designed to drop into a cron job or CI step:

| Code | Meaning                                                            |
|------|-------------------------------------------------------------------|
| `0`  | Report produced, risk **LOW** (nothing notable).                  |
| `2`  | Report produced, but **MEDIUM / HIGH** risk was detected.         |
| `1`  | Usage / input error (bad `--since`, no readable lines, …).        |

```bash
# Fail a pipeline loudly when an attack is visible in today's logs
python -m logwatch --format auth /var/log/auth.log || echo "review the logs!"
```

## Detections explained

### Access logs

| Category            | What triggers it                                                   |
|---------------------|--------------------------------------------------------------------|
| `path_traversal`    | `../`, `..\`, or percent-encoded variants in the path/query.       |
| `sqli`              | `UNION SELECT`, `OR 1=1`, `' OR '1'='1`, `sleep()`, `; DROP TABLE`, `information_schema`, … |
| `xss`               | `<script`, `javascript:`, `onerror=`, `onload=` in the URL.        |
| `scanner_path`      | Requests to known recon paths (`/wp-admin`, `/.env`, `/phpmyadmin`, `/.git/`, `/cgi-bin/`, `/actuator`, …). |
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
at the end and drives the exit code. It is based on the volume and spread of
detections — not a black-box score — so you can reason about it.

## Project layout

```
logwatch/
├── logwatch/                 # the runnable package
│   ├── __init__.py
│   ├── __main__.py           # enables `python -m logwatch`
│   ├── cli.py                # argparse, file/gzip/stdin reading, dispatch
│   ├── parsers.py            # access-log & sshd line parsers (pure functions)
│   ├── detectors.py          # suspicious-request + brute-force heuristics
│   ├── analyzers.py          # streaming aggregators -> summary dicts
│   ├── report.py             # human-readable, coloured report rendering
│   └── colors.py             # tiny ANSI helper (TTY/NO_COLOR aware)
├── samples/                  # synthetic logs that work out of the box
│   ├── access.log            # normal traffic + traversal/SQLi/scanner lines
│   ├── access.log.gz         # the same, gzip-compressed (demonstrates .gz)
│   └── auth.log              # normal logins + an SSH brute-force burst
├── tests/                    # stdlib unittest suite (no network / heavy I/O)
│   ├── test_parsers.py
│   ├── test_detectors.py
│   ├── test_analyzers.py
│   └── test_cli.py
├── README.md
├── requirements.txt          # intentionally empty (zero deps)
└── .gitignore
```

The design keeps the layers cleanly separated: **parsers** say *what happened*,
**detectors** say *whether it is suspicious*, **analyzers** aggregate, and
**report** renders. Every layer except `cli` is pure (no I/O), which is what
makes the test suite fast and deterministic.

## Running the tests

```bash
# From the project root
python -m unittest discover -s tests -v

# Compile-check every source file
python -m py_compile logwatch/*.py tests/*.py
```

The suite (61 tests) covers the parsers, every detector category, the
brute-force window logic, the aggregators, format auto-detection, and the CLI
end-to-end (including gzip input, JSON output and the risk exit code).

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
