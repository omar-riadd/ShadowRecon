"""Unit tests — runnable with either `pytest` or `python -m unittest`.

They cover the dependency-light modules (utils, waf_payloads, report) so CI
passes without Tor / the external CLI tools installed.
"""
import sys
import unittest
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "src"))


import report
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

    def test_read_and_count_lines(self, ):
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

    def test_package_and_shim_waf_payloads_parity(self):
        from shadowrecon import waf_payloads as pkg_waf
        self.assertEqual(set(waf_payloads.BYPASS.keys()), set(pkg_waf.BYPASS.keys()))
        for key, builder in waf_payloads.BYPASS.items():
            pkg_builder = pkg_waf.BYPASS[key]
            self.assertEqual(builder("https://example.com/"), pkg_builder("https://example.com/"))
        self.assertEqual(
            waf_payloads.default_payloads("https://example.com/"),
            pkg_waf.default_payloads("https://example.com/"),
        )


class TestReport(unittest.TestCase):
    def test_generate_builds_html_with_counts(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            run = Path(d)
            (run / "subdomains.txt").write_text("a.example.com\nb.example.com\n", encoding="utf-8")
            (run / "live.txt").write_text("https://a.example.com\n", encoding="utf-8")
            (run / "ffuf_dirs").mkdir()
            (run / "ffuf_dirs" / "host.csv").write_text("x", encoding="utf-8")

            sections = {s.title: s.count for s in report.collect(run)}
            self.assertEqual(sections["Subdomains"], 2)
            self.assertEqual(sections["Live hosts"], 1)
            self.assertEqual(sections["Directory fuzz (FFUF)"], 1)

            out = report.generate(run, {"Target": "https://example.com/"})
            self.assertTrue(out.exists())
            html = out.read_text(encoding="utf-8")
            self.assertIn("ShadowRecon", html)
            self.assertIn("Subdomains", html)


class TestBypassContext(unittest.TestCase):
    def test_dalfox_args(self):
        import main
        b = main.BypassContext(headers={"X-Forwarded-For": "127.0.0.1"})
        args = b.dalfox_args()
        self.assertEqual(args, ["--header", "X-Forwarded-For: 127.0.0.1"])

    def test_sqlmap_args(self):
        import main
        b = main.BypassContext(headers={"X-Forwarded-For": "127.0.0.1", "User-Agent": "Googlebot"})
        args = b.sqlmap_args()
        self.assertEqual(args, ["--headers", "X-Forwarded-For: 127.0.0.1\nUser-Agent: Googlebot"])

    def test_ffuf_args(self):
        import main
        b = main.BypassContext(headers={"X-Forwarded-For": "127.0.0.1"})
        args = b.ffuf_args()
        self.assertEqual(args, ["-H", "X-Forwarded-For: 127.0.0.1"])

    def test_empty_args(self):
        import main
        b = main.BypassContext()
        self.assertEqual(b.dalfox_args(), [])
        self.assertEqual(b.sqlmap_args(), [])
        self.assertEqual(b.ffuf_args(), [])


class TestParamSpiderPath(unittest.TestCase):
    def test_paramspider_reads_results_dir(self):
        import os
        import tempfile
        import main

        with tempfile.TemporaryDirectory() as d:
            old_cwd = os.getcwd()
            os.chdir(d)
            try:
                results_dir = Path("results")
                results_dir.mkdir()
                (results_dir / "api.example.com.txt").write_text(
                    "https://api.example.com/v1?user=FUZZ\nhttps://other.com/bad?x=1\n",
                    encoding="utf-8"
                )
                live = Path("live.txt")
                live.write_text("https://api.example.com\n", encoding="utf-8")
                params = Path("params.txt")
                params.write_text("", encoding="utf-8")

                cfg = main.Config(
                    target="https://example.com/",
                    domain="example.com",
                    wordlist=Path("w.txt"),
                    outdir=Path(d),
                    dry_run=True,
                )
                main.run_paramspider(cfg, live, params)

                lines = utils.read_lines(params)
                self.assertEqual(len(lines), 1)
                self.assertIn("user=FUZZ", lines[0])
            finally:
                os.chdir(old_cwd)


class TestResolveHttpx(unittest.TestCase):
    def test_resolve_httpx_finds_available_binary(self):
        import main
        binary = main.resolve_httpx()
        self.assertIn(binary, ("httpx-toolkit", "httpx", str(Path.home() / "go" / "bin" / "httpx")))


class TestConsole(unittest.TestCase):
    def test_console_import_and_status_card(self):
        import console
        from shadowrecon import console as pkg_console

        card = pkg_console.format_status_card(
            target="https://example.com/",
            domain="example.com",
            proxy_name="tor",
            proxy_url="socks5://127.0.0.1:9050",
            cb_stats={"healthy_hosts": 4, "tripped_hosts": 1, "probing_hosts": 0, "tripped_list": ["dead.example.com"]},
            stage_durations={"waf": 0.05, "subdomains": 0.10},
            findings_count=2,
        )
        self.assertIn("example.com", card)
        self.assertIn("Proxy Provider   : tor", card)
        self.assertIn("4 Healthy | 1 Tripped", card)
        self.assertIn("dead.example.com", card)
        self.assertIn("Findings Recorded: 2", card)

        self.assertEqual(callable(console.banner), callable(pkg_console.banner))
        self.assertEqual(callable(console.summary_table), callable(pkg_console.summary_table))


if __name__ == "__main__":
    unittest.main(verbosity=2)



