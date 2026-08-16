"""
Unit Tests for Remediation Engine & Roadmap Generator
"""
import unittest
from winsecure.remediation import RemediationEngine, RoadmapOrganizer
from winsecure.models import Finding, Severity, FindingStatus, RemediationPriority


class TestRemediation(unittest.TestCase):
    def test_remediation_generation(self):
        findings = [
            Finding(
                id="WS-DEF-001",
                title="Real-Time Protection Disabled",
                category="Defender",
                severity=Severity.CRITICAL,
                status=FindingStatus.FAIL,
                confidence=0.99,
                description="desc", expected="exp", actual="act", impact="imp", remediation="rem"
            ),
            Finding(
                id="WS-ACC-003",
                title="Lockout Threshold Unset",
                category="Accounts",
                severity=Severity.HIGH,
                status=FindingStatus.FAIL,
                confidence=0.95,
                description="desc", expected="exp", actual="act", impact="imp", remediation="rem"
            )
        ]
        remediations = RemediationEngine.generate_remediations(findings)
        self.assertEqual(len(remediations), 2)
        self.assertEqual(remediations[0].priority, RemediationPriority.P0_IMMEDIATE)
        self.assertIn("Set-MpPreference", remediations[0].powershell_script)

    def test_roadmap_organization(self):
        findings = [
            Finding(
                id="WS-DEF-001", title="RTP", category="Defender", severity=Severity.CRITICAL,
                status=FindingStatus.FAIL, confidence=0.99, description="", expected="", actual="", impact="", remediation=""
            ),
            Finding(
                id="WS-FW-001", title="FW", category="Firewall", severity=Severity.CRITICAL,
                status=FindingStatus.FAIL, confidence=0.99, description="", expected="", actual="", impact="", remediation=""
            )
        ]
        remediations = RemediationEngine.generate_remediations(findings)
        roadmap = RoadmapOrganizer.organize_roadmap(remediations)
        self.assertEqual(len(roadmap["Immediate (P0)"]), 2)


if __name__ == "__main__":
    unittest.main()
