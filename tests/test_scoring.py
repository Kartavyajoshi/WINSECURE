"""
Unit Tests for Risk Scoring and Anomaly Engines
"""
import unittest
from winsecure.scoring import RiskEngine, AnomalyEngine
from winsecure.models import Finding, Severity, FindingStatus, RiskLevel


class TestRiskAndAnomaly(unittest.TestCase):
    def test_perfect_score(self):
        findings = [
            Finding(
                id=f"WS-TEST-00{i}",
                title=f"Passing Test {i}",
                category="Defender",
                severity=Severity.MEDIUM,
                status=FindingStatus.PASS,
                confidence=1.0,
                description="", expected="", actual="", impact="", remediation=""
            ) for i in range(5)
        ]
        score, risk_lvl, deductions = RiskEngine.calculate_score(findings)
        self.assertEqual(score, 100.0)
        self.assertEqual(risk_lvl, RiskLevel.EXCELLENT)
        self.assertEqual(len(deductions), 0)

    def test_critical_deductions(self):
        findings = [
            Finding(
                id="WS-DEF-001",
                title="RTP Disabled",
                category="Defender",
                severity=Severity.CRITICAL,
                status=FindingStatus.FAIL,
                confidence=1.0,
                description="", expected="", actual="Disabled", impact="", remediation=""
            ),
            Finding(
                id="WS-FW-001",
                title="Public FW Disabled",
                category="Firewall",
                severity=Severity.CRITICAL,
                status=FindingStatus.FAIL,
                confidence=1.0,
                description="", expected="", actual="Disabled", impact="", remediation=""
            )
        ]
        score, risk_lvl, deductions = RiskEngine.calculate_score(findings)
        self.assertLess(score, 70.0)
        self.assertEqual(len(deductions), 2)
        self.assertEqual(deductions[0].points_deducted, 18.0) # 15 * 1.2

    def test_anomaly_detection(self):
        findings = [
            Finding(
                id="WS-DEF-001", title="", category="Defender", severity=Severity.CRITICAL,
                status=FindingStatus.FAIL, confidence=1.0, description="", expected="", actual="", impact="", remediation=""
            ),
            Finding(
                id="WS-RDP-001", title="", category="Remote Access", severity=Severity.HIGH,
                status=FindingStatus.FAIL, confidence=1.0, description="", expected="", actual="", impact="", remediation=""
            )
        ]
        anomalies = AnomalyEngine.detect_anomalies(findings)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["id"], "ANOMALY-001")


if __name__ == "__main__":
    unittest.main()
