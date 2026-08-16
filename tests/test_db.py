"""
Unit Tests for SQLite Storage and Repository Layer
"""
import os
import tempfile
import unittest
from winsecure.storage import DatabaseManager, ScanRepository
from winsecure.models import ScanResult, Finding, Severity, FindingStatus, RiskLevel


class TestDatabaseStorage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_scans.db")
        self.db_mgr = DatabaseManager(self.db_path)
        self.repo = ScanRepository(self.db_mgr)

    def tearDown(self):
        if hasattr(self, "db_mgr"):
            self.db_mgr.close()
        self.temp_dir.cleanup()

    def test_database_creation_and_integrity(self):
        self.assertTrue(os.path.exists(self.db_path))
        self.assertTrue(self.db_mgr.check_integrity())

    def test_save_and_retrieve_scan(self):
        finding = Finding(
            id="WS-DEF-001",
            title="Defender RTP Disabled",
            category="Defender",
            severity=Severity.CRITICAL,
            status=FindingStatus.FAIL,
            confidence=0.99,
            description="Defender is disabled",
            expected="True",
            actual="False",
            impact="Malware execution",
            remediation="Enable RTP"
        )
        scan = ScanResult(
            scan_id="SCAN-TEST001",
            timestamp="2026-08-16T12:00:00Z",
            winsecure_version="1.0.0",
            profile="standard",
            is_admin=True,
            security_score=78.5,
            risk_level=RiskLevel.MODERATE,
            findings=[finding]
        )

        self.repo.save_scan_result(scan)
        scans = self.repo.get_latest_scans(limit=5)
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["scan_id"], "SCAN-TEST001")
        self.assertEqual(scans[0]["security_score"], 78.5)


if __name__ == "__main__":
    unittest.main()
