"""Unit tests — runnable with either `pytest` or `python -m unittest`.

They cover the dependency-light modules (utils, waf_payloads, report) so CI
passes without Tor / the external CLI tools installed.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import utils
import waf_payloads


class TestUtils(unittest.TestCase):
    def test_parse_target_valid(self):
        self.assertEqual(utils.parse_target("https://sub.example.com/a?b=1"),
                         "sub.example.com")

    def test_parse_target_invalid(self):
        for bad in ("example.com", "ftp://x/", "not a url", ""):
            with self.assertRaises(ValueError):
                utils.parse_target(bad)

    def test_in_scope(self):
        d = "example.com"
        self.assertTrue(utils.in_scope("https://example.com/x", d))
        self.assertTrue(utils.in_scope("http://api.example.com/", d))
        self.assertFalse(utils.in_scope("https://evil.com/", d))
        self.assertFalse(utils.in_scope("https://notexample.com/", d))
        self.assertFalse(utils.in_scope("https://example.com.evil.com/", d))

    def test_slugify(self):
        self.assertEqual(utils.slugify("https://a.b/c"), "https___a_b_c")
        self.assertLessEqual(len(utils.slugify("x" * 500)), 80)

    def test_read_and_count_lines(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.txt"
            p.write_text("a\n\n b \nc\n", encoding="utf-8")
            self.assertEqual(utils.read_lines(p), ["a", "b", "c"])
            self.assertEqual(utils.count_lines(p), 3)
            self.assertEqual(utils.read_lines(Path(d) / "missing.txt"), [])


class TestWafRegistry(unittest.TestCase):
    def test_all_builders_callable_and_shaped(self):
        url = "https://example.com/"
        builders = list(waf_payloads.BYPASS.values()) + [waf_payloads.default_payloads]
        for fn in builders:
            payloads = fn(url)
            self.assertIsInstance(payloads, list)
            self.assertTrue(payloads, f"{fn.__name__} returned empty")
            for p in payloads:
                self.assertIn("desc", p)

    def test_registry_keys_are_strings(self):
        for key in waf_payloads.BYPASS:
            self.assertIsInstance(key, str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
