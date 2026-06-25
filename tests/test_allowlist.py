"""Unit tests for the allow-list and its integration with the detectors/analysers."""

import unittest
from datetime import datetime, timedelta, timezone

from logwatch.analyzers import AccessAnalyzer, AuthAnalyzer
from logwatch.detectors import AllowList, detect_bruteforce, risk_rank
from logwatch.parsers import AuthEvent


class TestAllowList(unittest.TestCase):
    def test_empty_allowlist_matches_nothing(self):
        al = AllowList([])
        self.assertFalse(al)
        self.assertEqual(len(al), 0)
        self.assertFalse(al.contains("8.8.8.8"))

    def test_single_ip_entry(self):
        al = AllowList(["198.51.100.7"])
        self.assertTrue(al.contains("198.51.100.7"))
        self.assertFalse(al.contains("198.51.100.8"))

    def test_cidr_range(self):
        al = AllowList(["10.0.0.0/8"])
        self.assertTrue(al.contains("10.1.2.3"))
        self.assertTrue(al.contains("10.255.255.254"))
        self.assertFalse(al.contains("11.0.0.1"))

    def test_ipv6_entry(self):
        al = AllowList(["2001:db8::/32"])
        self.assertTrue(al.contains("2001:db8::1"))
        self.assertFalse(al.contains("2001:dead::1"))

    def test_mixed_v4_v6_no_crash(self):
        al = AllowList(["10.0.0.0/8", "::1"])
        self.assertTrue(al.contains("10.0.0.5"))
        self.assertTrue(al.contains("::1"))
        # An IPv4 address must not be matched against an IPv6 network.
        self.assertFalse(al.contains("192.0.2.1"))

    def test_non_ip_value_is_never_allowed(self):
        al = AllowList(["10.0.0.0/8"])
        self.assertFalse(al.contains("not-an-ip"))
        self.assertFalse(al.contains("-"))

    def test_comments_and_blanks_skipped(self):
        al = AllowList(["# a comment", "", "  ", "203.0.113.0/24"])
        self.assertTrue(al.contains("203.0.113.10"))
        self.assertEqual(al.bad_entries, [])

    def test_bad_entries_recorded_not_raised(self):
        al = AllowList(["not-a-cidr", "10.0.0.0/8", "999.999.0.0/16"])
        self.assertEqual(len(al), 1)
        self.assertIn("not-a-cidr", al.bad_entries)
        self.assertIn("999.999.0.0/16", al.bad_entries)

    def test_whitespace_trimmed(self):
        al = AllowList(["  192.168.1.0/24  "])
        self.assertTrue(al.contains("192.168.1.50"))


class TestAllowListInBruteforce(unittest.TestCase):
    def _auth(self, ip, when, user="admin"):
        return AuthEvent(
            time=when, kind="failed", user=user, ip=ip,
            invalid_user=True, method="password", raw="",
        )

    def test_allowlisted_ip_not_flagged_as_bruteforce(self):
        base = datetime(2024, 10, 10, 9, 0, 0, tzinfo=timezone.utc)
        events = [self._auth("10.0.0.5", base + timedelta(seconds=i)) for i in range(20)]
        # Without the allow-list it is a clear brute-force hit.
        self.assertEqual(len(detect_bruteforce(events, threshold=5)), 1)
        # With the allow-list covering the source, it disappears.
        al = AllowList(["10.0.0.0/8"])
        self.assertEqual(detect_bruteforce(events, threshold=5, allow=al), [])

    def test_only_allowlisted_ip_removed(self):
        base = datetime(2024, 10, 10, 9, 0, 0, tzinfo=timezone.utc)
        good = [self._auth("10.0.0.5", base + timedelta(seconds=i)) for i in range(10)]
        bad = [self._auth("45.13.7.99", base + timedelta(seconds=i)) for i in range(10)]
        al = AllowList(["10.0.0.0/8"])
        hits = detect_bruteforce(good + bad, threshold=5, allow=al)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].ip, "45.13.7.99")


class TestAllowListInAnalyzers(unittest.TestCase):
    def test_access_suppresses_and_counts(self):
        lines = [
            '192.0.2.66 - - [10/Oct/2024:13:57:01 +0000] '
            '"GET /index.php?page=../../etc/passwd HTTP/1.1" 404 162 "-" "curl"',
            '185.220.101.4 - - [10/Oct/2024:13:58:01 +0000] '
            '"GET /.env HTTP/1.1" 404 153 "-" "zgrab"',
        ]
        al = AllowList(["192.0.2.66"])
        an = AccessAnalyzer(allow=al)
        for line in lines:
            an.feed_line(line)
        data = an.result()
        # The traversal from the allow-listed IP is suppressed; the .env probe
        # from the other IP still fires.
        self.assertEqual(data["suspicious"]["total"], 1)
        self.assertEqual(data["suspicious"]["suppressed"], 1)
        # Traffic stats still include both requests (allow-list != ignore).
        self.assertEqual(data["parsed"], 2)

    def test_auth_suppresses_attacker(self):
        lines = [
            f"Oct 10 09:12:{2 * i:02d} web01 sshd[{1000 + i}]: "
            f"Failed password for invalid user u{i} from 10.0.0.9 port 5{i:04d} ssh2"
            for i in range(8)
        ]
        al = AllowList(["10.0.0.0/8"])
        an = AuthAnalyzer(allow=al, assume_year=2024)
        for line in lines:
            an.feed_line(line)
        data = an.result()
        self.assertEqual(data["bruteforce"]["hits"], [])
        self.assertEqual(data["suppressed"], 8)
        # failed_logins still counts the raw events (visibility), but the IP is
        # absent from the attack leaderboard.
        self.assertEqual(data["failed_logins"], 8)
        self.assertEqual(data["top_attacking_ips"], [])


class TestRiskRank(unittest.TestCase):
    def test_ordering(self):
        self.assertLess(risk_rank("LOW"), risk_rank("MEDIUM"))
        self.assertLess(risk_rank("MEDIUM"), risk_rank("HIGH"))

    def test_unknown_label_is_lowest(self):
        self.assertEqual(risk_rank("WAT"), 0)


if __name__ == "__main__":
    unittest.main()
