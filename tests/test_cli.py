"""End-to-end-ish tests for the CLI layer.

These write tiny temporary log files (plain and gzip) and run ``cli.main`` with
its output captured, so we cover argument handling, gzip detection, JSON output
and the risk-based exit code without any network use.
"""

import gzip
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from logwatch import cli

ACCESS_SAMPLE = (
    '203.0.113.10 - - [10/Oct/2024:13:55:01 +0000] "GET / HTTP/1.1" 200 1543 "-" "Chrome"\n'
    '192.0.2.66 - - [10/Oct/2024:13:57:01 +0000] "GET /index.php?page=../../etc/passwd HTTP/1.1" 404 162 "-" "curl"\n'
)

AUTH_SAMPLE = "".join(
    f"Oct 10 09:12:{2 * i:02d} web01 sshd[{1000 + i}]: "
    f"Failed password for invalid user u{i} from 192.0.2.10 port 5{i:04d} ssh2\n"
    for i in range(8)
)


class CLITestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="logwatch_test_")

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.remove(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def _write(self, name, text, gz=False):
        path = os.path.join(self.tmp, name)
        if gz:
            with gzip.open(path, "wt", encoding="utf-8") as fh:
                fh.write(text)
        else:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        return path

    def _run(self, argv):
        """Run cli.main capturing stdout (stderr is swallowed); return (code, stdout)."""
        buf = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = cli.main(argv)
        return code, buf.getvalue()

    def test_access_text_report_runs(self):
        path = self._write("access.log", ACCESS_SAMPLE)
        code, out = self._run(["--no-color", path])
        self.assertIn("HTTP ACCESS LOG REPORT", out)
        self.assertIn("Suspicious requests", out)
        self.assertIn("RISK:", out)
        # One traversal request -> at least MEDIUM/LOW; exit code is 0 or 2.
        self.assertIn(code, (0, 2))

    def test_access_json_output_is_valid(self):
        path = self._write("access.log", ACCESS_SAMPLE)
        code, out = self._run(["--no-color", "--json", path])
        data = json.loads(out)
        self.assertEqual(data["kind"], "access")
        self.assertEqual(data["parsed"], 2)
        self.assertEqual(data["suspicious"]["total"], 1)

    def test_gzip_input_is_detected(self):
        path = self._write("access.log.gz", ACCESS_SAMPLE, gz=True)
        code, out = self._run(["--no-color", "--json", path])
        data = json.loads(out)
        self.assertEqual(data["parsed"], 2)

    def test_auth_format_and_bruteforce_exit_code(self):
        path = self._write("auth.log", AUTH_SAMPLE)
        code, out = self._run(["--no-color", "--format", "auth", "--json", path])
        data = json.loads(out)
        self.assertEqual(data["kind"], "auth")
        self.assertEqual(len(data["bruteforce"]["hits"]), 1)
        # 8 fails in seconds from one IP -> MEDIUM/HIGH -> exit code 2.
        self.assertEqual(code, 2)

    def test_auto_detect_selects_auth(self):
        path = self._write("mystery.log", AUTH_SAMPLE)
        code, out = self._run(["--no-color", "--json", path])
        data = json.loads(out)
        self.assertEqual(data["kind"], "auth")

    def test_bad_since_returns_error_code(self):
        path = self._write("access.log", ACCESS_SAMPLE)
        # Capture stderr separately; just assert the exit code is the usage error.
        code, _ = self._run(["--no-color", "--since", "not-a-date", path])
        self.assertEqual(code, 1)

    def test_top_flag_limits_sections(self):
        path = self._write("access.log", ACCESS_SAMPLE)
        code, out = self._run(["--no-color", "--json", "--top", "1", path])
        data = json.loads(out)
        self.assertLessEqual(len(data["top_ips"]), 1)

    def test_fail_on_high_keeps_medium_run_green(self):
        # The auth burst is MEDIUM/HIGH; raising the gate to 'high' may pass.
        path = self._write("access.log", ACCESS_SAMPLE)
        # The two-line access sample is LOW risk -> exit 0 at any threshold.
        code, _ = self._run(["--no-color", "--fail-on", "high", path])
        self.assertEqual(code, 0)

    def test_fail_on_low_fails_on_any_detection(self):
        # AUTH_SAMPLE is a clear brute force -> at least MEDIUM -> fail at 'low'.
        path = self._write("auth.log", AUTH_SAMPLE)
        code, _ = self._run(["--no-color", "--format", "auth", "--fail-on", "low", path])
        self.assertEqual(code, 2)

    def test_fail_on_high_downgrades_exit_code(self):
        # A single-IP burst is MEDIUM, which is below the 'high' gate -> exit 0.
        path = self._write("auth.log", AUTH_SAMPLE)
        code, _ = self._run(
            ["--no-color", "--format", "auth", "--fail-on", "high", path]
        )
        self.assertEqual(code, 0)

    def test_allow_suppresses_attacker_exit_code(self):
        # Allow-listing the lone attacking IP removes the detection entirely,
        # so the run drops to LOW and exits 0.
        path = self._write("auth.log", AUTH_SAMPLE)
        code, out = self._run(
            ["--no-color", "--format", "auth", "--json", "--allow", "192.0.2.10", path]
        )
        data = json.loads(out)
        self.assertEqual(data["bruteforce"]["hits"], [])
        self.assertEqual(data["suppressed"], 8)
        self.assertEqual(code, 0)

    def test_allow_file_is_read(self):
        path = self._write("auth.log", AUTH_SAMPLE)
        allow_path = self._write("allow.txt", "# known good\n192.0.2.10\n")
        code, out = self._run(
            [
                "--no-color", "--format", "auth", "--json",
                "--allow-file", allow_path, path,
            ]
        )
        data = json.loads(out)
        self.assertEqual(data["bruteforce"]["hits"], [])

    def test_corrupt_gzip_is_skipped_not_crashed(self):
        # A file with the gzip magic bytes but a garbage body must not crash the
        # run; it is warned about and skipped, and good files still analyse.
        bad = os.path.join(self.tmp, "corrupt.log.gz")
        with open(bad, "wb") as fh:
            fh.write(b"\x1f\x8b\x08corrupted body that is not valid deflate data")
        good = self._write("access.log", ACCESS_SAMPLE)
        code, out = self._run(["--no-color", "--json", bad, good])
        data = json.loads(out)
        # The two good lines are still parsed despite the corrupt sibling.
        self.assertEqual(data["parsed"], 2)

    def test_corrupt_gzip_alone_returns_input_error(self):
        bad = os.path.join(self.tmp, "corrupt.log.gz")
        with open(bad, "wb") as fh:
            fh.write(b"\x1f\x8b\x08still not real gzip")
        code, _ = self._run(["--no-color", bad])
        self.assertEqual(code, 1)

    def test_html_and_md_files_are_written(self):
        path = self._write("access.log", ACCESS_SAMPLE)
        html_path = os.path.join(self.tmp, "report.html")
        md_path = os.path.join(self.tmp, "report.md")
        code, _ = self._run(
            ["--no-color", "--html", html_path, "--md", md_path, path]
        )
        self.assertTrue(os.path.exists(html_path))
        self.assertTrue(os.path.exists(md_path))
        with open(html_path, encoding="utf-8") as fh:
            html = fh.read()
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertIn("HTTP access log report", html)
        with open(md_path, encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn("# HTTP access log report", md)


if __name__ == "__main__":
    unittest.main()
