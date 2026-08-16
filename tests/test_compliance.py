"""
Unit Tests for Compliance Engine & Benchmark Mappings
"""
import unittest
from winsecure.compliance import ComplianceEngine
from winsecure.models import Finding, Severity, FindingStatus


class TestComplianceEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ComplianceEngine()

    def test_benchmark_loading(self):
        self.assertGreater(len(self.engine.controls), 3)
        self.assertIn("CIS Windows 11 Enterprise", self.engine.controls)

    def test_compliance_evaluation(self):
        f1 = Finding(
            id="WS-DEF-001",
            title="Real Time Protection",
            category="Defender",
            severity=Severity.CRITICAL,
            status=FindingStatus.PASS,
            confidence=0.99,
            description="desc", expected="exp", actual="act", impact="imp", remediation="rem"
        )
        f2 = Finding(
            id="WS-FW-001",
            title="Public Firewall",
            category="Firewall",
            severity=Severity.CRITICAL,
            status=FindingStatus.FAIL,
            confidence=0.99,
            description="desc", expected="exp", actual="act", impact="imp", remediation="rem"
        )

        summaries = self.engine.evaluate([f1, f2])
        self.assertGreater(len(summaries), 0)
        cis = next(s for s in summaries if "CIS Windows 11 Enterprise" in s.framework)
        self.assertGreater(cis.total_controls, 0)
        self.assertGreaterEqual(cis.compliance_percentage, 0.0)


if __name__ == "__main__":
    unittest.main()
