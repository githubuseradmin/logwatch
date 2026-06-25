"""Unit tests for the HTML and Markdown exporters.

These render real analyser result dicts and assert on the structure of the
output: that it is well-formed, that hostile log fields are escaped, and that
the GeoIP-free disclaimer is present.
"""

import unittest
from html.parser import HTMLParser

from logwatch.analyzers import AccessAnalyzer, AuthAnalyzer
from logwatch.exporters import (
    ASN_DISCLAIMER,
    render_html,
    render_markdown,
)

ACCESS_LINES = [
    '203.0.113.10 - - [10/Oct/2024:13:55:01 +0000] "GET / HTTP/1.1" 200 1543 "-" "Chrome"',
    '192.0.2.66 - - [10/Oct/2024:13:57:01 +0000] '
    '"GET /index.php?page=../../etc/passwd HTTP/1.1" 404 162 "-" "curl"',
    '185.220.101.4 - - [10/Oct/2024:13:58:01 +0000] "GET /.env HTTP/1.1" 404 153 "-" "zgrab"',
]

AUTH_LINES = [
    f"Oct 10 09:12:{2 * i:02d} web01 sshd[{1000 + i}]: "
    f"Failed password for invalid user u{i} from 192.0.2.10 port 5{i:04d} ssh2"
    for i in range(8)
]


def _access_data():
    an = AccessAnalyzer(top_n=5)
    for line in ACCESS_LINES:
        an.feed_line(line)
    return an.result()


def _auth_data():
    an = AuthAnalyzer(top_n=5, assume_year=2024)
    for line in AUTH_LINES:
        an.feed_line(line)
    return an.result()


class _WellFormed(HTMLParser):
    """Minimal balance checker: every non-void open tag must be closed in order."""

    VOID = {"meta", "br", "hr", "img", "input", "link", "area", "base", "col"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.balanced = True

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
        else:
            self.balanced = False


class TestHtmlExport(unittest.TestCase):
    def _assert_well_formed(self, html):
        p = _WellFormed()
        p.feed(html)
        self.assertTrue(p.balanced, "tags are not balanced")
        self.assertEqual(p.stack, [], f"unclosed tags: {p.stack}")

    def test_access_html_is_well_formed(self):
        html = render_html(_access_data(), 5)
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertIn("HTTP access log report", html)
        self.assertIn("RISK:", html)
        self._assert_well_formed(html)

    def test_auth_html_is_well_formed(self):
        html = render_html(_auth_data(), 5)
        self.assertIn("SSH auth log report", html)
        self.assertIn("Brute-force suspects", html)
        self._assert_well_formed(html)

    def test_html_is_self_contained(self):
        # No external assets: no remote src/href, no <script>.
        html = render_html(_access_data(), 5)
        self.assertNotIn("http://", html.replace("HTTP/", ""))
        self.assertNotIn("<script", html.lower())
        self.assertIn("<style>", html)

    def test_html_escapes_hostile_fields(self):
        # A path carrying an XSS probe must be escaped, not rendered as a tag.
        line = (
            '203.0.113.9 - - [10/Oct/2024:13:55:01 +0000] '
            '"GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 10 "-" "x"'
        )
        an = AccessAnalyzer(top_n=5)
        an.feed_line(line)
        html = render_html(an.result(), 5)
        # The raw, unescaped script tag must NOT appear; the escaped form must.
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_html_contains_disclaimer(self):
        html = render_html(_access_data(), 5)
        # The disclaimer's distinctive phrase survives HTML-escaping intact.
        self.assertIn("does not resolve IP ownership", html)


class TestMarkdownExport(unittest.TestCase):
    def test_access_markdown_structure(self):
        md = render_markdown(_access_data(), 5)
        self.assertIn("# HTTP access log report", md)
        self.assertIn("## Overview", md)
        self.assertIn("| IP | Requests |", md)
        self.assertIn("Risk:", md)
        self.assertIn(ASN_DISCLAIMER, md)

    def test_auth_markdown_structure(self):
        md = render_markdown(_auth_data(), 5)
        self.assertIn("# SSH auth log report", md)
        self.assertIn("Brute-force suspects", md)
        self.assertIn("192.0.2.10", md)

    def test_markdown_escapes_pipe(self):
        # A path containing a pipe must not break table columns.
        line = (
            '203.0.113.9 - - [10/Oct/2024:13:55:01 +0000] '
            '"GET /a|b HTTP/1.1" 200 10 "-" "x"'
        )
        an = AccessAnalyzer(top_n=5)
        an.feed_line(line)
        md = render_markdown(an.result(), 5)
        self.assertIn("/a\\|b", md)


if __name__ == "__main__":
    unittest.main()
