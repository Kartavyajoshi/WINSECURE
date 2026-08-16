"""
Unit Tests for Golden Test Fixtures (Hardened vs Default vs Weak)
"""
import os
import unittest
from winsecure.core.config import ScanConfig
from winsecure.core.context import ScanContext
from winsecure.engine.pipeline import ScanPipeline
from winsecure.models import FindingStatus, RiskLevel


class TestGoldenFixtures(unittest.TestCase):
    def setUp(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_hardened_fixture(self):
        fix_path = os.path.join(self.base_dir, "fixtures", "hardened.json")
        config = ScanConfig(output_dir="/tmp/ws_test_hardened", fixture_path=fix_path)
        ctx = ScanContext(config=config)
        pipeline = ScanPipeline(ctx)
        result = pipeline.run()

        self.assertGreaterEqual(result.security_score, 90.0)
        self.assertEqual(result.risk_level, RiskLevel.EXCELLENT)
        fail_count = sum(1 for f in result.findings if f.status == FindingStatus.FAIL)
        self.assertEqual(fail_count, 0)

    def test_weak_fixture(self):
        fix_path = os.path.join(self.base_dir, "fixtures", "weak.json")
        config = ScanConfig(output_dir="/tmp/ws_test_weak", fixture_path=fix_path)
        ctx = ScanContext(config=config)
        pipeline = ScanPipeline(ctx)
        result = pipeline.run()

        self.assertLess(result.security_score, 50.0)
        self.assertEqual(result.risk_level, RiskLevel.CRITICAL)
        self.assertGreater(len(result.anomalies), 0)
        self.assertGreater(len(result.remediations), 5)


if __name__ == "__main__":
    unittest.main()
