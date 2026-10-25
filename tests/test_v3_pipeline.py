"""Unit tests for ShadowRecon v3 pipeline runner, streaming queue, and stage filtering."""
import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from shadowrecon.config import BypassContext, Config
from shadowrecon.core.executor import AsyncExecutor
from shadowrecon.core.tor import TorManager
from shadowrecon.pipeline.queue import AsyncEventBus, Event
from shadowrecon.pipeline.runner import (
    PipelineExecutionError,
    PipelineRunner,
    StageContext,
    StageResult,
    should_run_stage,
)
from shadowrecon.storage.session import SessionStore


class TestStageFiltering(unittest.TestCase):
    def test_default_all(self):
        self.assertTrue(should_run_stage("waf", "all", ""))
        self.assertTrue(should_run_stage("subdomains", "all", ""))
        self.assertTrue(should_run_stage("fuzzing", "", ""))

    def test_specific_stages(self):
        self.assertTrue(should_run_stage("waf", "waf,subdomains", ""))
        self.assertTrue(should_run_stage("subdomains", "waf, subdomains", ""))
        self.assertFalse(should_run_stage("fuzzing", "waf,subdomains", ""))

    def test_skip_stages(self):
        self.assertFalse(should_run_stage("fuzzing", "all", "fuzzing,sqlmap"))
        self.assertFalse(should_run_stage("sqlmap", "all", "fuzzing,sqlmap"))
        self.assertTrue(should_run_stage("waf", "all", "fuzzing,sqlmap"))

    def test_skip_overrides_include(self):
        # Even if specifically requested in stages, skip_stages wins
        self.assertFalse(should_run_stage("waf", "waf,subdomains", "waf"))
        self.assertTrue(should_run_stage("subdomains", "waf,subdomains", "waf"))


class TestAsyncEventBus(unittest.IsolatedAsyncioTestCase):
    async def test_publish_and_subscribe(self):
        bus = AsyncEventBus()
        sub_host = bus.subscribe("host")
        sub_all = bus.subscribe("*")

        ev1 = await bus.publish("host", "https://api.example.com", source="httpx")
        self.assertEqual(ev1.topic, "host")
        self.assertEqual(ev1.data, "https://api.example.com")

        ev2 = await bus.publish("subdomain", "admin.example.com", source="subfinder")

        # sub_host only gets ev1
        got_host = await sub_host.get()
        self.assertEqual(got_host.data, "https://api.example.com")

        # sub_all gets both
        got_all_1 = await sub_all.get()
        got_all_2 = await sub_all.get()
        self.assertEqual(got_all_1.data, "https://api.example.com")
        self.assertEqual(got_all_2.data, "admin.example.com")

        await bus.close()

    async def test_stream_generator(self):
        bus = AsyncEventBus()

        async def producer():
            await asyncio.sleep(0.01)
            await bus.publish("subdomain", "sub1.example.com")
            await bus.publish("subdomain", "sub2.example.com")
            await bus.close_topic("subdomain")

        asyncio.create_task(producer())

        items = []
        async for ev in bus.stream("subdomain"):
            items.append(ev.data)

        self.assertEqual(items, ["sub1.example.com", "sub2.example.com"])
        await bus.close()


class TestPipelineRunner(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.db_path = self.root / "session.db"
        self.store = SessionStore(self.db_path)
        self.config = Config(
            target="https://example.com/",
            domain="example.com",
            wordlist=self.root / "wordlist.txt",
            outdir=self.root / "output",
            dry_run=True,
            use_proxy=False,
        )
        self.executor = AsyncExecutor(dry_run=True, use_proxy=False)
        self.tor = TorManager(dry_run=True)
        self.bus = AsyncEventBus()
        self.bypass_ctx = BypassContext()

        self.ctx = StageContext(
            config=self.config,
            store=self.store,
            executor=self.executor,
            bus=self.bus,
            tor=self.tor,
            bypass_context=self.bypass_ctx,
        )

    def tearDown(self):
        self.tmpdir.cleanup()

    async def test_sequential_success(self):
        runner = PipelineRunner()
        executed = []

        async def stage1(ctx):
            executed.append("stage1")
            ctx.store.add_subdomains(["api.example.com"])

        async def stage2(ctx):
            executed.append("stage2")
            ctx.store.add_hosts(["https://api.example.com"])

        runner.add_stage("subdomains", "Find subdomains", stage1)
        runner.add_stage("probing", "Probe live hosts", stage2)

        results = await runner.run(self.ctx)

        self.assertEqual(executed, ["stage1", "stage2"])
        self.assertTrue(results["subdomains"].success)
        self.assertTrue(results["probing"].success)
        self.assertTrue(self.store.is_stage_completed("subdomains"))
        self.assertTrue(self.store.is_stage_completed("probing"))

    async def test_stage_resumption(self):
        # Pre-mark stage as completed
        self.store.set_stage("subdomains", "completed", duration=5.0)

        runner = PipelineRunner()
        executed = []

        async def stage1(ctx):
            executed.append("stage1")

        async def stage2(ctx):
            executed.append("stage2")

        runner.add_stage("subdomains", "Find subdomains", stage1)
        runner.add_stage("probing", "Probe live hosts", stage2)

        results = await runner.run(self.ctx)

        # stage1 was resumed (skipped), stage2 ran
        self.assertEqual(executed, ["stage2"])
        self.assertEqual(results["subdomains"].status, "resumed")
        self.assertEqual(results["probing"].status, "completed")

    async def test_stage_resumption_overridden_by_force_rerun(self):
        self.store.set_stage("subdomains", "completed", duration=5.0)
        self.config.force_rerun = True

        runner = PipelineRunner()
        executed = []

        async def stage1(ctx):
            executed.append("stage1")

        runner.add_stage("subdomains", "Find subdomains", stage1)
        results = await runner.run(self.ctx)

        self.assertEqual(executed, ["stage1"])
        self.assertEqual(results["subdomains"].status, "completed")

    async def test_fault_isolation_non_required_stage(self):
        runner = PipelineRunner()
        executed = []

        async def stage_failing(ctx):
            executed.append("failing")
            raise ConnectionError("Simulated network timeout")

        async def stage_subsequent(ctx):
            executed.append("subsequent")

        runner.add_stage("failing_stage", "Test failing", stage_failing, required=False)
        runner.add_stage("subsequent_stage", "Subsequent stage", stage_subsequent, required=False)

        results = await runner.run(self.ctx)

        self.assertIn("failing", executed)
        self.assertIn("subsequent", executed)
        self.assertEqual(results["failing_stage"].status, "failed")
        self.assertIn("Simulated network timeout", results["failing_stage"].error_message)
        self.assertEqual(results["subsequent_stage"].status, "completed")

    async def test_required_stage_aborts_pipeline(self):
        runner = PipelineRunner()
        executed = []

        async def stage_critical(ctx):
            executed.append("critical")
            raise ValueError("Critical auth failure")

        async def stage_after(ctx):
            executed.append("after")

        runner.add_stage("critical_stage", "Critical check", stage_critical, required=True)
        runner.add_stage("after_stage", "After stage", stage_after, required=False)

        with self.assertRaises(PipelineExecutionError):
            await runner.run(self.ctx)

        self.assertEqual(executed, ["critical"])
        self.assertNotIn("after", executed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
