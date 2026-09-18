"""
WinSecure Drift & Trend Analytics Engine
Analyzes security posture across N historical scans to detect trends,
recurring defects, and long-term posture trajectory.
"""
from typing import Any, Dict, List, Optional

from winsecure.storage.db import DatabaseManager
from winsecure.storage.repository import ScanRepository


class TrendDirection:
    """Trend direction constants."""
    IMPROVING = "IMPROVING"
    DECLINING = "DECLINING"
    STABLE = "STABLE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class DriftTrendEngine:
    """Detects security posture trends and recurring defects across scan history."""

    # Minimum scans required before a trend can be computed
    MIN_SCANS_FOR_TREND = 3

    def __init__(self, db_path: str):
        self.db_manager = DatabaseManager(db_path)
        self.repository = ScanRepository(self.db_manager)

    def close(self) -> None:
        """Releases the underlying database handle."""
        self.db_manager.close()

    def get_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Returns recent scans ordered oldest -> newest for trend analysis."""
        scans = self.repository.get_latest_scans(limit=limit)
        return list(reversed(scans))

    def analyze_trend(self, limit: int = 20) -> Dict[str, Any]:
        """Computes score trend, volatility, and posture direction over history."""
        history = self.get_history(limit=limit)

        if len(history) < 2:
            return {
                "has_history": False,
                "scans_analyzed": len(history),
                "direction": TrendDirection.INSUFFICIENT_DATA,
                "message": "Need at least 2 persisted scans to compute a trend.",
            }

        scores = [float(s.get("security_score", 0.0)) for s in history]
        timestamps = [s.get("timestamp", "") for s in history]
        scan_ids = [s.get("scan_id", "") for s in history]

        first_score = scores[0]
        last_score = scores[-1]
        net_change = round(last_score - first_score, 1)

        deltas = [round(scores[i + 1] - scores[i], 1) for i in range(len(scores) - 1)]
        improving_steps = sum(1 for d in deltas if d > 0)
        declining_steps = sum(1 for d in deltas if d < 0)

        avg_score = round(sum(scores) / len(scores), 1)
        best_score = max(scores)
        worst_score = min(scores)
        volatility = round(max(scores) - min(scores), 1)

        if len(history) >= self.MIN_SCANS_FOR_TREND:
            if declining_steps > improving_steps and net_change < 0:
                direction = TrendDirection.DECLINING
            elif improving_steps > declining_steps and net_change > 0:
                direction = TrendDirection.IMPROVING
            else:
                direction = TrendDirection.STABLE
        else:
            direction = TrendDirection.STABLE

        return {
            "has_history": True,
            "scans_analyzed": len(history),
            "scan_ids": scan_ids,
            "timestamps": timestamps,
            "scores": scores,
            "first_score": first_score,
            "last_score": last_score,
            "net_change": net_change,
            "average_score": avg_score,
            "best_score": best_score,
            "worst_score": worst_score,
            "volatility": volatility,
            "improving_steps": improving_steps,
            "declining_steps": declining_steps,
            "direction": direction,
            "message": (
                f"Posture is {direction.lower()} over {len(history)} scans "
                f"(net {net_change:+0.1f} pts, avg {avg_score})."
            ),
        }

    def find_recurring_failures(self, limit: int = 20, min_occurrences: int = 2) -> List[Dict[str, Any]]:
        """Identifies findings that failed repeatedly across the scan history."""
        history = self.get_history(limit=limit)
        occurrence_counts: Dict[str, Dict[str, Any]] = {}

        for scan in history:
            scan_id = scan.get("scan_id")
            if not scan_id:
                continue
            failed_ids = self._get_failed_finding_ids(scan_id)
            for fid in failed_ids:
                entry = occurrence_counts.setdefault(
                    fid,
                    {"finding_id": fid, "occurrences": 0, "scan_ids": []},
                )
                entry["occurrences"] += 1
                entry["scan_ids"].append(scan_id)

        recurring = [
            e for e in occurrence_counts.values()
            if e["occurrences"] >= min_occurrences
        ]
        recurring.sort(key=lambda e: (-e["occurrences"], e["finding_id"]))
        return recurring

    def _get_failed_finding_ids(self, scan_id: str) -> List[str]:
        """Fetches FAIL finding IDs for one stored scan."""
        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM findings WHERE scan_id = ? AND status = 'FAIL'",
                (scan_id,),
            )
            return [row["id"] for row in cursor.fetchall()]

    def build_full_report(self, limit: int = 20) -> Dict[str, Any]:
        """Aggregates trend analysis and recurring failures into one payload."""
        report = self.analyze_trend(limit=limit)
        report["recurring_failures"] = self.find_recurring_failures(limit=limit)
        return report
