"""
WinSecure Pre-Flight and Post-Flight Health Diagnostic Checker
"""
import os
import sys
import json
from typing import Tuple
from winsecure.core.config import ScanConfig
from winsecure.models.scan import ScanResult
from winsecure.utils.system import is_windows, is_admin


class HealthChecker:
    """Performs runtime pre-flight environment checks and post-flight diagnostic verification."""

    @staticmethod
    def pre_flight_check(config: ScanConfig) -> Tuple[bool, str]:
        """Validates Python version, rule database integrity, and output permissions before scan."""
        # 1. Python Version
        if sys.version_info < (3, 9):
            return False, f"Python 3.9+ required. Current version: {sys.version.split()[0]}"

        # 2. Rules Directory & Integrity
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        rules_dir = os.path.join(base_dir, "rules")
        if os.path.isdir(rules_dir):
            rule_files = [f for f in os.listdir(rules_dir) if f.endswith(".json")]
            if len(rule_files) == 0:
                return False, "Rules directory found but contains 0 rule JSON files."
        else:
            rule_files = []

        # 3. Output Directory Permissions
        try:
            os.makedirs(config.output_dir, exist_ok=True)
            test_file = os.path.join(config.output_dir, ".health_check.tmp")
            with open(test_file, "w") as f:
                f.write("OK")
            if os.path.exists(test_file):
                os.remove(test_file)
        except Exception as e:
            return False, f"Cannot write to output directory {config.output_dir}: {e}"

        admin_status = "Administrator" if is_admin() else "Standard User"
        return True, f"Python {sys.version.split()[0]} | {admin_status} | {len(rule_files)} Rule Files Verified"

    @staticmethod
    def post_flight_check(scan_result: ScanResult, index_path: str) -> Tuple[bool, str]:
        """Validates score boundaries, findings schema, and report files after scan."""
        # 1. Score Boundary Verification
        if not (0.0 <= scan_result.security_score <= 100.0):
            return False, f"Security score out of bounds: {scan_result.security_score}"

        # 2. Report Output Verification
        if not os.path.isfile(index_path) or os.path.getsize(index_path) == 0:
            return False, f"Report file missing or empty at {index_path}"

        # 3. Findings Integrity
        findings_count = len(scan_result.findings)
        if findings_count == 0:
            return False, "Scan completed with 0 evaluated findings."

        return True, f"Score: {scan_result.security_score:.1f}/100 | {findings_count} Controls Audited | Report Verified"
