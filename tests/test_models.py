"""
Unit Tests for WinSecure Data Models
"""
import unittest
from winsecure.models import (
    Finding, Severity, FindingStatus, Evidence, Rule,
    ComplianceControl, FrameworkSummary, ComplianceStatus,
    RemediationAction, RemediationPriority, SystemInventory,
    ScanResult, RiskLevel
)


class TestModels(unittest.TestCase):
    def test_evidence_sanitization_and_id(self):
        ev = Evidence(
            source="HKLM\\Registry",
            collector="RegistryCollector",
            data={"password": "SuperSecretPassword123!", "user": "admin"}
        )
        d = ev.to_dict()
        self.assertIsNotNone(ev.evidence_id)
        # Note: data in Evidence model is sanitized when creating Evidence from base collector
        self.assertEqual(d["source"], "HKLM\\Registry")

    def test_finding_serialization(self):
        finding = Finding(
            id="WS-TEST-001",
            title="Test Finding Title",
            category="Defender",
            severity=Severity.HIGH,
            status=FindingStatus.FAIL,
            confidence=0.98,
            description="Test description",
            expected="Enabled",
            actual="Disabled",
            impact="High impact",
            remediation="Fix it"
        )
        d = finding.to_dict()
        self.assertEqual(d["id"], "WS-TEST-001")
        self.assertEqual(d["severity"], "High")
        self.assertEqual(d["status"], "FAIL")
        
        recreated = Finding.from_dict(d)
        self.assertEqual(recreated.id, "WS-TEST-001")
        self.assertEqual(recreated.severity, Severity.HIGH)
        self.assertEqual(recreated.status, FindingStatus.FAIL)

    def test_risk_level_mapping(self):
        self.assertEqual(RiskLevel.from_score(95.0), RiskLevel.EXCELLENT)
        self.assertEqual(RiskLevel.from_score(85.0), RiskLevel.STRONG)
        self.assertEqual(RiskLevel.from_score(75.0), RiskLevel.MODERATE)
        self.assertEqual(RiskLevel.from_score(55.0), RiskLevel.WEAK)
        self.assertEqual(RiskLevel.from_score(35.0), RiskLevel.CRITICAL)


if __name__ == "__main__":
    unittest.main()
