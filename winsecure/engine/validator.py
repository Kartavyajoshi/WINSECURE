"""
WinSecure Result and Integrity Validator
"""
from typing import List, Tuple
from winsecure.models.scan import ScanResult


class ScanValidator:
    """Validates structural integrity, required fields, and score consistency."""

    @staticmethod
    def validate_scan_result(result: ScanResult) -> Tuple[bool, List[str]]:
        errors = []
        if not result.scan_id:
            errors.append("Missing scan_id")
        if result.security_score < 0.0 or result.security_score > 100.0:
            errors.append(f"Security score out of bounds: {result.security_score}")
        if not result.findings and not result.errors:
            errors.append("Scan completed with zero findings and zero errors")
        
        # Verify findings IDs uniqueness per scan
        ids = [f.id for f in result.findings]
        if len(ids) != len(set(ids)):
            errors.append("Duplicate finding IDs detected in results")

        return len(errors) == 0, errors
