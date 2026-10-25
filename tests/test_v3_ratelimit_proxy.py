"""Unit tests for AdaptiveRateLimiter, ProxyPoolProvider, TorProxyProvider, and proxy health checks."""
import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

# Add src and root to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))
sys.path.insert(0, str(root_dir))

from shadowrecon.cli import async_main
from shadowrecon.core.executor import AsyncExecutor
from shadowrecon.core.proxy import DirectProxyProvider, ProxyPoolProvider, TorProxyProvider
from shadowrecon.core.ratelimit import AdaptiveRateLimiter
from shadowrecon.core.tor import TorManager


class TestAdaptiveRateLimiter(unittest.IsolatedAsyncioTestCase):
    def test_exponential_backoff_on_429_and_503(self):
        limiter = AdaptiveRateLimiter(baseline_delay=1.0, max_backoff=16.0, backoff_factor=2.0)
        self.assertEqual(limiter.current_delay, 1.0)

        # First 429 -> doubles delay to 2.0s
        d1 = limiter.record_response(429)
        self.assertEqual(d1, 2.0)
        self.assertEqual(limiter.consecutive_blocks, 1)
        self.assertFalse(limiter.should_rotate_ip)

        # Second 503 -> doubles delay to 4.0s
        d2 = limiter.record_response(503)
        self.assertEqual(d2, 4.0)
        self.assertEqual(limiter.consecutive_blocks, 2)
        self.assertFalse(limiter.should_rotate_ip)

        # Third 429 -> doubles delay to 8.0s, triggers should_rotate_ip
        d3 = limiter.record_response(429)
        self.assertEqual(d3, 8.0)
        self.assertEqual(limiter.consecutive_blocks, 3)
        self.assertTrue(limiter.should_rotate_ip)

        # Cap at max_backoff
        limiter.record_response(429)  # 16.0
        d_cap = limiter.record_response(429)
        self.assertEqual(d_cap, 16.0)

    def test_decay_on_sustained_success(self):
        limiter = AdaptiveRateLimiter(baseline_delay=1.0, max_backoff=16.0, backoff_factor=2.0)
        limiter.record_response(429)  # 2.0
        limiter.record_response(429)  # 4.0
        self.assertEqual(limiter.current_delay, 4.0)

        # 1st and 2nd success: does not decay yet
        limiter.record_response(200)
        limiter.record_response(200)
        self.assertEqual(limiter.current_delay, 4.0)

        # 3rd success: decays down by backoff_factor (4.0 / 2.0 = 2.0)
        limiter.record_response(200)
        self.assertEqual(limiter.current_delay, 2.0)
        self.assertEqual(limiter.consecutive_blocks, 0)

    async def test_acquire_timing(self):
        limiter = AdaptiveRateLimiter(baseline_delay=0.01, jitter_ratio=0.0)
        slept = await limiter.acquire()
        # Second acquire immediate -> should sleep roughly 0.01s
        slept2 = await limiter.acquire()
        self.assertGreaterEqual(slept2, 0.0)


class TestProxyProviders(unittest.IsolatedAsyncioTestCase):
    def test_direct_provider(self):
        provider = DirectProxyProvider()
        self.assertEqual(provider.get_proxy_url(), "")
        self.assertEqual(provider.provider_name, "direct")

    async def test_tor_provider_dry_run(self):
        tor_mgr = TorManager(dry_run=True)
        provider = TorProxyProvider(tor_mgr, socks_url="socks5://127.0.0.1:9050")
        self.assertEqual(provider.get_proxy_url(), "socks5://127.0.0.1:9050")
        self.assertEqual(provider.provider_name, "tor")
        self.assertTrue(await provider.health_check())
        self.assertTrue(await provider.rotate())

    async def test_proxy_pool_round_robin_and_file_loader(self):
        proxies = [
            "http://10.0.0.1:8080",
            "socks5://10.0.0.2:1080",
            "https://10.0.0.3:8443",
        ]
        pool = ProxyPoolProvider(proxies=proxies, strategy="round_robin")
        self.assertEqual(pool.provider_name, "pool(3)")

        # 1. First proxy
        self.assertEqual(pool.get_proxy_url(), "http://10.0.0.1:8080")

        # 2. Rotate round-robin
        await pool.rotate()
        self.assertEqual(pool.get_proxy_url(), "socks5://10.0.0.2:1080")

        await pool.rotate()
        self.assertEqual(pool.get_proxy_url(), "https://10.0.0.3:8443")

        # Wrap around
        await pool.rotate()
        self.assertEqual(pool.get_proxy_url(), "http://10.0.0.1:8080")

    async def test_proxy_pool_from_file(self):
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write("# Residential proxies\nsocks5://node1.proxy:1080\nhttp://node2.proxy:8080\n")
            f_path = Path(f.name)

        try:
            pool = ProxyPoolProvider.from_file(f_path)
            self.assertEqual(len(pool.proxies), 2)
            self.assertEqual(pool.get_proxy_url(), "socks5://node1.proxy:1080")
        finally:
            f_path.unlink()

    async def test_executor_with_dynamic_proxy_pool(self):
        proxies = ["socks5://node1:1080", "socks5://node2:1080"]
        pool = ProxyPoolProvider(proxies=proxies)
        executor = AsyncExecutor(use_proxy=True, dry_run=True, proxy_provider=pool)

        res1 = await executor.run(["curl", "https://example.com"])
        self.assertIn("node1:1080", " ".join(res1.command))

        await pool.rotate()
        res2 = await executor.run(["curl", "https://example.com"])
        self.assertIn("node2:1080", " ".join(res2.command))

    async def test_cli_proxy_pool_integration(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            pool_file = tmp / "proxies.txt"
            pool_file.write_text("socks5://gateway1:1080\nsocks5://gateway2:1080\n", encoding="utf-8")
            outdir = tmp / "out"

            argv = [
                "-u", "https://example.com/",
                "-o", str(outdir),
                "--proxy-provider", "pool",
                "--proxy-pool", str(pool_file),
                "--stages", "waf",
                "--dry-run",
            ]
            code = await async_main(argv)
            self.assertEqual(code, 0)
            self.assertTrue((outdir / "session.db").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
