"""Unit tests for ShadowRecon Phase 5: Pluggable ScannerDriver architecture and Mock drivers."""
import sys
import tempfile
import unittest
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))
sys.path.insert(0, str(root_dir))

from shadowrecon.config import BypassContext, Config
from shadowrecon.core.executor import AsyncExecutor
from shadowrecon.core.tor import TorManager
from shadowrecon.drivers.base import ScanResult, ScannerDriver
from shadowrecon.drivers.mock import MockScannerDriver
from shadowrecon.drivers.registry import DriverRegistry
from shadowrecon.pipeline.queue import AsyncEventBus
from shadowrecon.pipeline.runner import StageContext
from shadowrecon.storage.session import FindingRecord, HostRecord, SessionStore


class DummyDriver(ScannerDriver):
    async def execute(self, ctx: StageContext, **kwargs) -> ScanResult:
        return ScanResult(success=True, raw_output="dummy ok")


class TestDriverBaseAndRegistry(unittest.TestCase):
    def test_scanner_driver_availability(self):
        # Python should be available on the system
        driver = DummyDriver("python_test", "python3")
        self.assertTrue(driver.is_available())

        # Nonexistent tool
        missing = DummyDriver("ghost_tool", "ghost_nonexistent_binary_xyz_123")
        self.assertFalse(missing.is_available())

    def test_registry_operations(self):
        reg = DriverRegistry()
        driver_a = DummyDriver("driver_a", "python3")
        driver_b = DummyDriver("driver_b", "python3")

        reg.register("subdomains", driver_a, is_default=True)
        reg.register("subdomains", driver_b)

        # Default driver
        self.assertEqual(reg.get_driver("subdomains").name, "driver_a")

        # Specific driver by name
        self.assertEqual(reg.get_driver("subdomains", "driver_b").name, "driver_b")

        # Set active driver
        reg.set_active("subdomains", "driver_b")
        self.assertEqual(reg.get_driver("subdomains").name, "driver_b")

        # List drivers
        listing = reg.list_drivers("subdomains")
        self.assertIn("driver_a", listing["subdomains"])
        self.assertIn("driver_b", listing["subdomains"])

        # Error on unregistered stage
        with self.assertRaises(KeyError):
            reg.get_driver("unknown_stage")


class TestMockScannerDriver(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.cfg = Config(
            target="https://example.com/",
            domain="example.com",
            wordlist=self.tmp / "wl.txt",
            outdir=self.tmp / "out",
            dry_run=True,
            use_proxy=False,
        )
        self.store = SessionStore(self.tmp / "session.db")
        self.executor = AsyncExecutor(dry_run=True, use_proxy=False)
        self.bus = AsyncEventBus()
        self.tor = TorManager(dry_run=True)
        self.ctx = StageContext(self.cfg, self.store, self.executor, self.bus, self.tor, BypassContext())

    def tearDown(self):
        self.tmpdir.cleanup()

    async def test_mock_driver_success_ingestion(self):
        synthetic_subs = ["api.example.com", "portal.example.com"]
        synthetic_findings = [
            FindingRecord(vuln_type="XSS", severity="high", target_url="https://api.example.com/item"),
        ]

        sub_driver = MockScannerDriver(
            name="mock_subfinder",
            synthetic_items=synthetic_subs,
            output_file_name="subdomains.txt",
        )
        vuln_driver = MockScannerDriver(
            name="mock_vuln",
            synthetic_items=synthetic_findings,
        )

        res_subs = await sub_driver.execute(self.ctx)
        self.assertTrue(res_subs.success)
        self.assertEqual(res_subs.items_count, 2)
        self.assertTrue((self.cfg.outdir / "subdomains.txt").is_file())
        self.assertEqual(self.store.get_subdomains(), ["api.example.com", "portal.example.com"])

        res_vulns = await vuln_driver.execute(self.ctx)
        self.assertTrue(res_vulns.success)
        self.assertEqual(res_vulns.items_count, 1)
        self.assertEqual(len(self.store.get_findings()), 1)

    async def test_mock_driver_failure_simulation(self):
        failing_driver = MockScannerDriver(
            name="failing_tool",
            should_succeed=False,
        )
        res = await failing_driver.execute(self.ctx)
        self.assertFalse(res.success)
        self.assertIn("simulated execution failure", res.error)


if __name__ == "__main__":
    unittest.main()
