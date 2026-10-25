"""Unit tests for ShadowRecon v3 core modules."""
import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from shadowrecon.config import BypassContext, Config, load_toml_config
from shadowrecon.core.executor import AsyncExecutor, inject_native_proxy, resolve_binary
from shadowrecon.core.scope import count_lines, in_scope, parse_target, read_lines, slugify
from shadowrecon.core.tor import TorManager


class TestV3Scope(unittest.TestCase):
    def test_parse_target_valid(self):
        self.assertEqual(parse_target("https://api.example.com/v1"), "api.example.com")

    def test_parse_target_invalid(self):
        for bad in ("ftp://test", "example.com", "http://", ""):
            with self.assertRaises(ValueError):
                parse_target(bad)

    def test_in_scope(self):
        d = "example.com"
        self.assertTrue(in_scope("https://example.com/login", d))
        self.assertTrue(in_scope("https://api.example.com/", d))
        self.assertFalse(in_scope("https://attacker.com/", d))
        self.assertFalse(in_scope("https://example.com.evil.com/", d))

    def test_slugify(self):
        self.assertEqual(slugify("https://target.com/a?b=1"), "https___target_com_a_b_1")

    def test_read_and_count_lines(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.txt"
            p.write_text("line1\n\nline2 \n", encoding="utf-8")
            self.assertEqual(read_lines(p), ["line1", "line2"])
            self.assertEqual(count_lines(p), 2)
            self.assertEqual(read_lines(Path(d) / "nonexistent.txt"), [])


class TestV3Tor(unittest.TestCase):
    def test_dry_run_rotate(self):
        tor = TorManager(dry_run=True)
        self.assertTrue(tor.rotate_circuit_sync())

    def test_rotate_without_password(self):
        tor = TorManager(control_password="", dry_run=False)
        self.assertFalse(tor.rotate_circuit_sync())

    def test_async_rotate(self):
        tor = TorManager(dry_run=True)
        res = asyncio.run(tor.rotate_circuit())
        self.assertTrue(res)


class TestV3Executor(unittest.TestCase):
    def test_resolve_binary_httpx(self):
        resolved = resolve_binary("httpx")
        self.assertIn(resolved, ("httpx-toolkit", "httpx", str(Path.home() / "go" / "bin" / "httpx")))

    def test_inject_native_proxy_flags(self):
        proxy = "socks5://127.0.0.1:9050"
        self.assertEqual(
            inject_native_proxy(["ffuf", "-w", "dict.txt"], proxy),
            ["ffuf", "-x", proxy, "-w", "dict.txt"],
        )
        self.assertEqual(
            inject_native_proxy(["httpx-toolkit", "-silent"], proxy),
            ["httpx-toolkit", "-http-proxy", proxy, "-silent"],
        )
        self.assertEqual(
            inject_native_proxy(["nuclei", "-t", "cves"], proxy),
            ["nuclei", "-proxy-socks-url", proxy, "-t", "cves"],
        )
        self.assertEqual(
            inject_native_proxy(["dalfox", "file", "urls.txt"], proxy),
            ["dalfox", "--proxy", proxy, "file", "urls.txt"],
        )
        self.assertEqual(
            inject_native_proxy(["sqlmap", "-u", "http://x"], proxy),
            ["sqlmap", f"--proxy={proxy}", "-u", "http://x"],
        )

    def test_async_executor_dry_run(self):
        executor = AsyncExecutor(dry_run=True)
        res = asyncio.run(executor.run(["subfinder", "-d", "example.com"]))
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout, "")


class TestV3Config(unittest.TestCase):
    def test_bypass_context_args(self):
        ctx = BypassContext(headers={"X-Forwarded-For": "127.0.0.1"})
        self.assertEqual(ctx.dalfox_args(), ["--header", "X-Forwarded-For: 127.0.0.1"])
        self.assertEqual(ctx.ffuf_args(), ["-H", "X-Forwarded-For: 127.0.0.1"])
        self.assertEqual(ctx.sqlmap_args(), ["--headers", "X-Forwarded-For: 127.0.0.1"])

    def test_load_toml_config(self):
        with tempfile.TemporaryDirectory() as d:
            cfg_file = Path(d) / "shadowrecon.toml"
            cfg_file.write_text('[shadowrecon]\nrate_limit = 1.5\nffuf_threads = 8\n', encoding="utf-8")
            loaded = load_toml_config(cfg_file)
            self.assertEqual(loaded.get("rate_limit"), 1.5)
            self.assertEqual(loaded.get("ffuf_threads"), 8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
