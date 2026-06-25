"""Unit tests for the log-line parsers.

These exercise the pure parsing functions against representative fixture lines.
No filesystem or network access is required.
"""

import unittest
from datetime import datetime

from logwatch.parsers import (
    AccessEntry,
    AuthEvent,
    parse_access_line,
    parse_auth_line,
)


class TestAccessParser(unittest.TestCase):
    def test_parses_standard_combined_line(self):
        line = (
            '203.0.113.10 - - [10/Oct/2024:13:55:01 +0000] '
            '"GET /index.html HTTP/1.1" 200 1543 '
            '"https://ref.example/" "Mozilla/5.0 (X11)"'
        )
        entry = parse_access_line(line)
        self.assertIsInstance(entry, AccessEntry)
        self.assertEqual(entry.ip, "203.0.113.10")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.path, "/index.html")
        self.assertEqual(entry.protocol, "HTTP/1.1")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.size, 1543)
        self.assertEqual(entry.referer, "https://ref.example/")
        self.assertEqual(entry.user_agent, "Mozilla/5.0 (X11)")

    def test_status_class_buckets(self):
        def status_for(code):
            line = (
                f'1.1.1.1 - - [10/Oct/2024:00:00:00 +0000] '
                f'"GET / HTTP/1.1" {code} 0 "-" "-"'
            )
            return parse_access_line(line).status_class

        self.assertEqual(status_for(200), "2xx")
        self.assertEqual(status_for(301), "3xx")
        self.assertEqual(status_for(404), "4xx")
        self.assertEqual(status_for(500), "5xx")

    def test_timestamp_is_parsed_with_timezone(self):
        line = (
            '1.1.1.1 - - [10/Oct/2024:13:55:01 +0000] '
            '"GET / HTTP/1.1" 200 10 "-" "-"'
        )
        entry = parse_access_line(line)
        self.assertIsInstance(entry.time, datetime)
        self.assertEqual(entry.time.year, 2024)
        self.assertEqual(entry.time.hour, 13)
        self.assertIsNotNone(entry.time.tzinfo)

    def test_dash_size_and_status_become_zero(self):
        # NGINX writes "-" for size on redirects/empty bodies.
        line = (
            '1.1.1.1 - - [10/Oct/2024:13:55:01 +0000] '
            '"GET / HTTP/1.1" 302 - "-" "-"'
        )
        entry = parse_access_line(line)
        self.assertEqual(entry.status, 302)
        self.assertEqual(entry.size, 0)

    def test_malformed_request_token_does_not_crash(self):
        # An attacker may send a single-token / empty request.
        line = (
            '1.1.1.1 - - [10/Oct/2024:13:55:01 +0000] '
            '"GET" 400 0 "-" "-"'
        )
        entry = parse_access_line(line)
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.path, "-")

    def test_non_matching_line_returns_none(self):
        self.assertIsNone(parse_access_line("this is not a log line"))
        self.assertIsNone(parse_access_line(""))
        self.assertIsNone(parse_access_line("   "))

    def test_missing_optional_quotes(self):
        # Some logs omit referer/agent entirely.
        line = (
            '1.1.1.1 - - [10/Oct/2024:13:55:01 +0000] '
            '"GET / HTTP/1.1" 200 10'
        )
        entry = parse_access_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.referer, "")
        self.assertEqual(entry.user_agent, "")


class TestAuthParser(unittest.TestCase):
    def test_failed_invalid_user(self):
        line = (
            "Oct 10 09:12:01 web01 sshd[1123]: Failed password for "
            "invalid user admin from 192.0.2.10 port 50344 ssh2"
        )
        ev = parse_auth_line(line, assume_year=2024)
        self.assertIsInstance(ev, AuthEvent)
        self.assertEqual(ev.kind, "failed")
        self.assertEqual(ev.user, "admin")
        self.assertEqual(ev.ip, "192.0.2.10")
        self.assertTrue(ev.invalid_user)

    def test_failed_existing_user(self):
        line = (
            "Oct 10 09:12:19 web01 sshd[1132]: Failed password for "
            "root from 192.0.2.10 port 50480 ssh2"
        )
        ev = parse_auth_line(line, assume_year=2024)
        self.assertEqual(ev.kind, "failed")
        self.assertEqual(ev.user, "root")
        self.assertFalse(ev.invalid_user)

    def test_accepted_publickey(self):
        line = (
            "Oct 10 08:00:01 web01 sshd[1010]: Accepted publickey for "
            "deploy from 198.51.100.7 port 51001 ssh2: RSA SHA256:abc123"
        )
        ev = parse_auth_line(line, assume_year=2024)
        self.assertEqual(ev.kind, "accepted")
        self.assertEqual(ev.user, "deploy")
        self.assertEqual(ev.ip, "198.51.100.7")
        self.assertEqual(ev.method, "publickey")

    def test_invalid_user_notice(self):
        line = (
            "Oct 10 09:12:02 web01 sshd[1123]: Invalid user admin "
            "from 192.0.2.10 port 50344"
        )
        ev = parse_auth_line(line, assume_year=2024)
        self.assertEqual(ev.kind, "invalid")
        self.assertEqual(ev.user, "admin")
        self.assertTrue(ev.invalid_user)

    def test_timestamp_built_with_assumed_year(self):
        line = (
            "Jun 24 09:12:01 host sshd[1]: Failed password for "
            "root from 10.0.0.1 port 22 ssh2"
        )
        ev = parse_auth_line(line, assume_year=2026)
        self.assertEqual(ev.time.year, 2026)
        self.assertEqual(ev.time.month, 6)
        self.assertEqual(ev.time.day, 24)
        self.assertEqual(ev.time.hour, 9)

    def test_non_sshd_lines_ignored(self):
        self.assertIsNone(
            parse_auth_line(
                "Oct 10 12:00:00 web01 sudo: alice : COMMAND=/usr/bin/apt"
            )
        )
        self.assertIsNone(parse_auth_line("Oct 10 12:01:30 web01 systemd[1]: Started Session"))
        self.assertIsNone(parse_auth_line(""))


if __name__ == "__main__":
    unittest.main()
