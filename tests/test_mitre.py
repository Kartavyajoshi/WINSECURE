"""
Unit Tests for MITRE ATT&CK Exporter
"""
import json
import os
import tempfile
import unittest
from winsecure.models import ScanResult, Finding, Severity, FindingStatus, RiskLevel
from winsecure.reporting.mitre_exporter import MitreAttackExporter


class TestMitreExporter(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_mitre_export_structure(self):
        f = Finding(
            id="WS-DEF-001",
            title="Real-Time Protection Disabled",
            category="Defender",
            severity=Severity.CRITICAL,
            status=FindingStatus.FAIL,
            confidence=0.99,
            description="Defender RTP is disabled",
            expected="True",
            actual="False",
            impact="Malware execution",
            remediation="Enable RTP",
            mitre_attack=["T1562.001"]
        )
        scan = ScanResult(
            scan_id="SCAN-001",
            timestamp="2026-08-16T12:00:00Z",
            winsecure_version="1.0.0",
            profile="standard",
            is_admin=True,
            security_score=80.0,
            risk_level=RiskLevel.STRONG,
            findings=[f]
        )

        mitre_file = MitreAttackExporter.export(scan, self.temp_dir.name)
        self.assertTrue(os.path.isfile(mitre_file))

        with open(mitre_file, "r", encoding="utf-8") as f_in:
            data = json.load(f_in)
            self.assertGreaterEqual(data["total_techniques_mapped"], 1)
            self.assertEqual(data["failing_techniques_count"], 1)


if __name__ == "__main__":
    unittest.main()
