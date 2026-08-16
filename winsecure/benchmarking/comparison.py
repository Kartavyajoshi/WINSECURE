"""
WinSecure Historical Scan Comparison & Posture Drift Engine
"""
from typing import Any, Dict, List, Optional


class ScanComparison:
    """Compares current scan against previous scans to track security drift."""

    @staticmethod
    def compare_scans(current_scan: Dict[str, Any], previous_scan: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not previous_scan:
            return {
                "has_previous": False,
                "score_delta": 0.0,
                "message": "Initial scan — no prior baseline scan found for comparison."
            }

        prev_score = float(previous_scan.get("security_score", 100.0))
        curr_score = float(current_scan.get("security_score", 100.0))
        delta = round(curr_score - prev_score, 1)

        curr_fail_ids = {f["id"] for f in current_scan.get("findings", []) if f.get("status") == "FAIL"}
        prev_fail_ids = {f["id"] for f in previous_scan.get("findings", []) if f.get("status") == "FAIL"}

        fixed = list(prev_fail_ids - curr_fail_ids)
        regressed = list(curr_fail_ids - prev_fail_ids)

        return {
            "has_previous": True,
            "previous_scan_id": previous_scan.get("scan_id"),
            "previous_timestamp": previous_scan.get("timestamp"),
            "previous_score": prev_score,
            "current_score": curr_score,
            "score_delta": delta,
            "fixed_findings_count": len(fixed),
            "fixed_findings": fixed,
            "new_findings_count": len(regressed),
            "new_findings": regressed,
            "posture_improved": delta > 0,
            "message": f"Score changed by {delta:+0.1f} pts ({len(fixed)} fixed, {len(regressed)} new defects)."
        }
