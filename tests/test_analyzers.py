"""Unit tests for the aggregating analysers and format detection.

These feed fixture lines through the analysers and assert on the resulting
summary dicts. No real files are read.
"""

import unittest
from datetime import datetime, timezone

from logwatch.analyzers import AccessAnalyzer, AuthAnalyzer
from logwatch.cli import detect_format

ACCESS_LINES = [
    '203.0.113.10 - - [10/Oct/2024:13:55:01 +0000] "GET / HTTP/1.1" 200 1543 "-" "Chrome"',
    '203.0.113.10 - - [10/Oct/2024:13:55:02 +0000] "GET /a.css HTTP/1.1" 200 800 "-" "Chrome"',
    '198.51.100.23 - - [10/Oct/2024:13:55:04 +0000] "GET /products HTTP/1.1" 404 120 "-" "Safari"',
    '192.0.2.66 - - [10/Oct/2024:13:57:01 +0000] "GET /index.php?page=../../etc/passwd HTTP/1.1" 404 162 "-" "curl"',
    '185.220.101.4 - - [10/Oct/2024:13:58:01 +0000] "GET /.env HTTP/1.1" 404 153 "-" "zgrab"',
    '198.51.100.23 - - [10/Oct/2024:13:56:05 +0000] "GET /big.pdf HTTP/1.1" 200 5000000 "-" "Safari"',
]

AUTH_LINES = [
    "Oct 10 08:00:01 web01 sshd[1010]: Accepted publickey for deploy from 198.51.100.7 port 51001 ssh2",
    "Oct 10 09:12:01 web01 sshd[1123]: Failed password for invalid user admin from 192.0.2.10 port 50344 ssh2",
    "Oct 10 09:12:03 web01 sshd[1124]: Failed password for invalid user root from 192.0.2.10 port 50360 ssh2",
    "Oct 10 09:12:05 web01 sshd[1125]: Failed password for invalid user oracle from 192.0.2.10 port 50372 ssh2",
    "Oct 10 09:12:07 web01 sshd[1126]: Failed password for invalid user postgres from 192.0.2.10 port 50388 ssh2",
    "Oct 10 09:12:09 web01 sshd[1127]: Failed password for invalid user test from 192.0.2.10 port 50401 ssh2",
    "Oct 10 12:00:00 web01 sudo: alice : COMMAND=/usr/bin/apt",
]


class TestAccessAnalyzer(unittest.TestCase):
    def setUp(self):
        self.an = AccessAnalyzer(top_n=5)
        for line in ACCESS_LINES:
            self.an.feed_line(line)
        self.data = self.an.result()

    def test_counts(self):
        self.assertEqual(self.data["kind"], "access")
        self.assertEqual(self.data["parsed"], 6)
        self.assertEqual(self.data["unparsed"], 0)
        self.assertEqual(self.data["unique_ips"], 4)

    def test_status_classes(self):
        self.assertEqual(self.data["status_classes"]["2xx"], 3)
        self.assertEqual(self.data["status_classes"]["4xx"], 3)

    def test_top_ip_is_most_frequent(self):
        top_ip, count = self.data["top_ips"][0]
        # Two IPs have 2 requests; just assert the leader has count 2.
        self.assertEqual(count, 2)

    def test_suspicious_detected(self):
        self.assertEqual(self.data["suspicious"]["total"], 2)
        cats = dict(self.data["suspicious"]["by_category"])
        self.assertIn("path_traversal", cats)
        self.assertIn("scanner_path", cats)
        # The /.env request is both a recon path and a sensitive-file probe.
        self.assertIn("sensitive_file", cats)

    def test_biggest_response_first(self):
        self.assertEqual(self.data["biggest_responses"][0]["size"], 5000000)

    def test_since_filter_drops_old_rows(self):
        cutoff = datetime(2024, 10, 10, 13, 57, 0, tzinfo=timezone.utc)
        an = AccessAnalyzer(top_n=5, since=cutoff)
        for line in ACCESS_LINES:
            an.feed_line(line)
        data = an.result()
        # Only the two rows at/after 13:57 survive (traversal + .env).
        self.assertEqual(data["parsed"], 2)
        self.assertGreaterEqual(data["skipped_since"], 1)

    def test_unparsed_counted(self):
        an = AccessAnalyzer()
        an.feed_line("garbage line that is not a log")
        self.assertEqual(an.result()["unparsed"], 1)
        self.assertEqual(an.result()["parsed"], 0)


class TestAuthAnalyzer(unittest.TestCase):
    def setUp(self):
        self.an = AuthAnalyzer(top_n=5, bf_threshold=5, bf_window=5, assume_year=2024)
        for line in AUTH_LINES:
            self.an.feed_line(line)
        self.data = self.an.result()

    def test_counts(self):
        self.assertEqual(self.data["kind"], "auth")
        self.assertEqual(self.data["failed_logins"], 5)
        self.assertEqual(self.data["accepted_logins"], 1)

    def test_bruteforce_hit(self):
        hits = self.data["bruteforce"]["hits"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["ip"], "192.0.2.10")
        self.assertEqual(hits[0]["failed_count"], 5)

    def test_invalid_users_collected(self):
        users = dict(self.data["top_invalid_users"])
        self.assertIn("admin", users)
        self.assertIn("root", users)

    def test_accepted_user_summary(self):
        accepted = dict(self.data["accepted_users"])
        self.assertEqual(accepted.get("deploy"), 1)

    def test_risk_label_present(self):
        self.assertIn(self.data["risk"], ("LOW", "MEDIUM", "HIGH"))


class TestFormatDetection(unittest.TestCase):
    def test_detects_access(self):
        self.assertEqual(detect_format(ACCESS_LINES), "access")

    def test_detects_auth(self):
        self.assertEqual(detect_format(AUTH_LINES), "auth")

    def test_empty_defaults_to_access(self):
        self.assertEqual(detect_format([]), "access")


if __name__ == "__main__":
    unittest.main()
