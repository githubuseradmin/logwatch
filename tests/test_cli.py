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
from contextlib import redirect_stdout

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
        """Run cli.main capturing stdout; return (exit_code, stdout_text)."""
        buf = io.StringIO()
        with redirect_stdout(buf):
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


if __name__ == "__main__":
    unittest.main()
