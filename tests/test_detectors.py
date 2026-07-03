"""Unit tests for the security detectors (suspicious requests + brute force)."""

import unittest
from datetime import datetime, timedelta, timezone

from logwatch.detectors import (
    BruteForceHit,
    classify_ip,
    classify_suspicious,
    detect_bruteforce,
    summarize_risk_access,
    summarize_risk_auth,
)
from logwatch.parsers import AccessEntry, AuthEvent, parse_access_line


def _access(path, method="GET", status=200):
    """Build an AccessEntry for a given request path (helper for tests)."""
    return AccessEntry(
        ip="192.0.2.66",
        user="-",
        time=None,
        method=method,
        path=path,
        protocol="HTTP/1.1",
        status=status,
        size=0,
        referer="",
        user_agent="test",
        raw="",
    )


class TestSuspiciousClassifier(unittest.TestCase):
    def test_clean_request_not_flagged(self):
        self.assertIsNone(classify_suspicious(_access("/products/42")))
        self.assertIsNone(classify_suspicious(_access("/api/cart", method="POST")))

    def test_path_traversal_plain(self):
        s = classify_suspicious(_access("/index.php?page=../../../../etc/passwd"))
        self.assertIsNotNone(s)
        self.assertIn("path_traversal", s.categories)

    def test_path_traversal_url_encoded(self):
        s = classify_suspicious(_access("/download?file=..%2f..%2f..%2fetc%2fshadow"))
        self.assertIsNotNone(s)
        self.assertIn("path_traversal", s.categories)

    def test_sqli_union_select(self):
        s = classify_suspicious(
            _access("/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users")
        )
        self.assertIsNotNone(s)
        self.assertIn("sqli", s.categories)

    def test_sqli_tautology(self):
        s = classify_suspicious(_access("/login?user=admin'%20OR%20'1'='1"))
        self.assertIsNotNone(s)
        self.assertIn("sqli", s.categories)

    def test_scanner_paths(self):
        for path in ("/wp-admin/", "/.env", "/phpmyadmin/index.php", "/.git/config"):
            s = classify_suspicious(_access(path))
            self.assertIsNotNone(s, path)
            self.assertIn("scanner_path", s.categories, path)

    def test_oversized_query(self):
        big = "/api?filter=" + "A" * 600
        s = classify_suspicious(_access(big))
        self.assertIsNotNone(s)
        self.assertIn("oversized_query", s.categories)

    def test_bad_method(self):
        s = classify_suspicious(_access("/", method="PROPFIND"))
        self.assertIsNotNone(s)
        self.assertIn("bad_method", s.categories)

    def test_xss(self):
        s = classify_suspicious(_access("/search?q=<script>alert(1)</script>"))
        self.assertIsNotNone(s)
        self.assertIn("xss", s.categories)

    def test_multiple_categories_on_one_request(self):
        # A scanner path that also carries SQLi should report both.
        s = classify_suspicious(_access("/phpmyadmin/?id=1%20OR%201=1"))
        self.assertIsNotNone(s)
        self.assertIn("scanner_path", s.categories)
        self.assertIn("sqli", s.categories)

    def test_sensitive_file_named_paths(self):
        # Each of these targets a secret/config/key/diagnostic file and must be
        # flagged as a sensitive-file probe.
        for path in (
            "/.env",
            "/.git/config",
            "/wp-config.php",
            "/.aws/credentials",
            "/id_rsa",
            "/.ssh/authorized_keys",
            "/.htpasswd",
            "/server-status",
            "/phpinfo.php",
            "/.DS_Store",
        ):
            s = classify_suspicious(_access(path))
            self.assertIsNotNone(s, path)
            self.assertIn("sensitive_file", s.categories, path)

    def test_sensitive_file_backup_and_dump_suffixes(self):
        # Config/db dumps and .bak/.old backups left in the docroot.
        for path in (
            "/backup.sql",
            "/db.sql.gz",
            "/wp-config.php.bak",
            "/index.php.old",
            "/app.db",
            "/private.key",
            "/cert.pem",
        ):
            s = classify_suspicious(_access(path))
            self.assertIsNotNone(s, path)
            self.assertIn("sensitive_file", s.categories, path)

    def test_sensitive_file_suffix_ignores_query_string(self):
        # The suffix test looks at the path, not a query string that merely
        # ends in a sensitive-looking extension.
        s = classify_suspicious(_access("/search?q=report.sql"))
        self.assertIsNone(s)

    def test_sensitive_file_url_encoded(self):
        s = classify_suspicious(_access("/%2eenv"))
        # %2e decodes to '.', so /%2eenv -> /.env
        self.assertIsNotNone(s)
        self.assertIn("sensitive_file", s.categories)

    def test_sensitive_file_clean_paths_not_flagged(self):
        # Benign paths that superficially resemble sensitive names must not fire.
        for path in (
            "/environment",           # not /.env
            "/products/config",       # no sensitive suffix, no sensitive path
            "/blog/backups-guide",    # word "backup" but no .backup suffix
            "/assets/app.js",
            "/keyboard",              # ends in "board", not a .key file
        ):
            self.assertIsNone(classify_suspicious(_access(path)), path)

    def test_sensitive_file_and_scanner_both_fire_for_dotenv(self):
        # /.env is both a recon path and a sensitive-file leak; report both.
        s = classify_suspicious(_access("/.env"))
        self.assertIsNotNone(s)
        self.assertIn("scanner_path", s.categories)
        self.assertIn("sensitive_file", s.categories)

    def test_real_attack_lines_from_sample(self):
        line = (
            '192.0.2.66 - - [10/Oct/2024:13:57:01 +0000] '
            '"GET /index.php?page=../../../../etc/passwd HTTP/1.1" 404 162 "-" "curl/7.88.1"'
        )
        entry = parse_access_line(line)
        s = classify_suspicious(entry)
        self.assertIsNotNone(s)
        self.assertEqual(s.ip, "192.0.2.66")


def _auth(ip, when, user="admin", kind="failed"):
    """Build an AuthEvent (helper for brute-force tests)."""
    return AuthEvent(
        time=when,
        kind=kind,
        user=user,
        ip=ip,
        invalid_user=True,
        method="password",
        raw="",
    )


class TestBruteForce(unittest.TestCase):
    def test_burst_inside_window_is_flagged(self):
        base = datetime(2024, 10, 10, 9, 12, 0, tzinfo=timezone.utc)
        events = [
            _auth("192.0.2.10", base + timedelta(seconds=2 * i), user=f"u{i}")
            for i in range(15)
        ]
        hits = detect_bruteforce(events, threshold=5, window_minutes=5)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].ip, "192.0.2.10")
        self.assertEqual(hits[0].failed_count, 15)
        self.assertGreaterEqual(hits[0].peak_in_window, 5)

    def test_spread_out_attempts_not_flagged_by_window(self):
        # 4 attempts, each an hour apart: below threshold in any 5-min window
        # AND below the total threshold of 5, so it should not be flagged.
        base = datetime(2024, 10, 10, 0, 0, 0, tzinfo=timezone.utc)
        events = [_auth("198.18.0.5", base + timedelta(hours=i)) for i in range(4)]
        hits = detect_bruteforce(events, threshold=5, window_minutes=5)
        self.assertEqual(hits, [])

    def test_total_threshold_catches_slow_scan(self):
        # 6 attempts over 6 hours: window peak is 1, but total >= threshold.
        base = datetime(2024, 10, 10, 0, 0, 0, tzinfo=timezone.utc)
        events = [_auth("198.18.0.9", base + timedelta(hours=i)) for i in range(6)]
        hits = detect_bruteforce(events, threshold=5, window_minutes=5)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].failed_count, 6)

    def test_accepted_logins_are_ignored(self):
        base = datetime(2024, 10, 10, 9, 0, 0, tzinfo=timezone.utc)
        events = [_auth("10.0.0.1", base, kind="accepted") for _ in range(10)]
        hits = detect_bruteforce(events, threshold=5, window_minutes=5)
        self.assertEqual(hits, [])

    def test_users_tried_collected_and_deduped(self):
        base = datetime(2024, 10, 10, 9, 0, 0, tzinfo=timezone.utc)
        events = [
            _auth("192.0.2.10", base + timedelta(seconds=i), user=u)
            for i, u in enumerate(["root", "admin", "root", "oracle", "admin", "git"])
        ]
        hits = detect_bruteforce(events, threshold=5, window_minutes=5)
        self.assertEqual(len(hits), 1)
        self.assertEqual(set(hits[0].users_tried), {"root", "admin", "oracle", "git"})

    def test_sorted_worst_first(self):
        base = datetime(2024, 10, 10, 9, 0, 0, tzinfo=timezone.utc)
        small = [_auth("1.1.1.1", base + timedelta(seconds=i)) for i in range(6)]
        large = [_auth("2.2.2.2", base + timedelta(seconds=i)) for i in range(20)]
        hits = detect_bruteforce(small + large, threshold=5, window_minutes=5)
        self.assertEqual(hits[0].ip, "2.2.2.2")


class TestClassifyIp(unittest.TestCase):
    def test_public(self):
        # Genuinely globally-routable addresses.
        self.assertEqual(classify_ip("8.8.8.8"), "public")
        self.assertEqual(classify_ip("185.220.101.4"), "public")

    def test_private(self):
        self.assertEqual(classify_ip("10.0.0.1"), "private")
        self.assertEqual(classify_ip("192.168.1.5"), "private")
        self.assertEqual(classify_ip("172.16.0.9"), "private")
        self.assertEqual(classify_ip("127.0.0.1"), "private")

    def test_ipv6(self):
        self.assertEqual(classify_ip("2001:4860:4860::8888"), "public")
        self.assertEqual(classify_ip("::1"), "private")

    def test_documentation_ranges_are_other(self):
        # TEST-NET-3 (203.0.113.0/24) is reserved for docs, not a real source.
        self.assertEqual(classify_ip("203.0.113.10"), "other")
        self.assertEqual(classify_ip("192.0.2.66"), "other")

    def test_non_ip(self):
        self.assertEqual(classify_ip("not-an-ip"), "other")
        self.assertEqual(classify_ip("-"), "other")

    def test_bruteforce_hit_carries_scope(self):
        base = datetime(2024, 10, 10, 9, 0, 0, tzinfo=timezone.utc)
        events = [_auth("192.168.0.50", base + timedelta(seconds=i)) for i in range(6)]
        hits = detect_bruteforce(events, threshold=5, window_minutes=5)
        self.assertEqual(hits[0].scope, "private")


class TestRiskSummaries(unittest.TestCase):
    def test_access_risk_levels(self):
        self.assertEqual(summarize_risk_access([], 100), "LOW")

    def test_access_risk_high_on_served_sensitive_file(self):
        # A single sensitive-file probe that returned 2xx (the secret was very
        # likely served) escalates the whole run to HIGH on its own.
        s = classify_suspicious(_access("/.env", status=200))
        self.assertIn("sensitive_file", s.categories)
        self.assertEqual(summarize_risk_access([s], 1000), "HIGH")

    def test_access_risk_not_high_when_sensitive_file_blocked(self):
        # The same probe answered with 404 is not a leak; a lone flagged
        # request stays LOW.
        s = classify_suspicious(_access("/.env", status=404))
        self.assertIn("sensitive_file", s.categories)
        self.assertEqual(summarize_risk_access([s], 1000), "LOW")

    def test_auth_risk_high_on_big_attack(self):
        hit = BruteForceHit(ip="x", failed_count=60, peak_in_window=60, users_tried=[])
        self.assertEqual(summarize_risk_auth([hit], 60), "HIGH")

    def test_auth_risk_low_when_clean(self):
        self.assertEqual(summarize_risk_auth([], 0), "LOW")


if __name__ == "__main__":
    unittest.main()
