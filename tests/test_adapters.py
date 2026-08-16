"""
Unit Tests for WinSecure Adapter Architecture
"""
import unittest
from winsecure.adapters import (
    HostDiscoveryAdapter,
    ServiceAnalyzerAdapter,
    ConfigAuditorAdapter,
    VulnerabilityAnalyzerAdapter,
    PolicyComplianceAdapter,
    ALL_ADAPTERS,
)
from winsecure.core.context import ScanContext
from winsecure.core.config import ScanConfig


class TestAdapterArchitecture(unittest.TestCase):
    """Verifies that all adapters adhere to the BaseAdapter schema and normalization contract."""

    def setUp(self):
        self.context = ScanContext(config=ScanConfig(fixture_path=None))

    def test_all_adapters_registered(self):
        self.assertEqual(len(ALL_ADAPTERS), 5)

    def test_host_discovery_adapter_schema(self):
        adapter = HostDiscoveryAdapter()
        res = adapter.execute("LAB-WIN-042", self.context)
        self.assertEqual(res["module"], "host_discovery")
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["target"], "LAB-WIN-042")
        self.assertIn("timestamp", res)
        self.assertIsInstance(res["metadata"], dict)

    def test_service_analyzer_adapter_schema(self):
        adapter = ServiceAnalyzerAdapter()
        res = adapter.execute("LAB-WIN-042", self.context)
        self.assertEqual(res["module"], "service_analyzer")
        self.assertEqual(res["status"], "completed")
        self.assertIsInstance(res["findings"], list)
        self.assertIsInstance(res["evidence"], list)

    def test_config_auditor_adapter_schema(self):
        adapter = ConfigAuditorAdapter()
        res = adapter.execute("LAB-WIN-042", self.context)
        self.assertEqual(res["module"], "config_auditor")
        self.assertEqual(res["status"], "completed")
        self.assertIn("threat_exposure", res["risk"])

    def test_vulnerability_adapter_schema(self):
        adapter = VulnerabilityAnalyzerAdapter()
        res = adapter.execute("LAB-WIN-042", self.context)
        self.assertEqual(res["module"], "vulnerability_analyzer")
        self.assertEqual(res["status"], "completed")

    def test_policy_compliance_adapter_schema(self):
        adapter = PolicyComplianceAdapter()
        res = adapter.execute("LAB-WIN-042", self.context)
        self.assertEqual(res["module"], "policy_compliance")
        self.assertEqual(res["status"], "completed")
        self.assertIn("overall_compliance_score", res["risk"])


if __name__ == "__main__":
    unittest.main()
