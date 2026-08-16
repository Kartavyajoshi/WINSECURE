"""
WinSecure Storage Repository
"""
import json
from typing import Any, Dict, List, Optional
from winsecure.models.finding import Finding
from winsecure.models.scan import ScanResult, ScoreDeduction
from winsecure.storage.db import DatabaseManager


class ScanRepository:
    """Provides high-level persistence for scan results."""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def save_scan_result(self, result: ScanResult) -> None:
        """Persists a complete ScanResult into SQLite."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            metrics = result.metrics
            inv = result.inventory

            # 1. Insert scan record
            cursor.execute("""
                INSERT OR REPLACE INTO scans (
                    scan_id, timestamp, winsecure_version, profile, is_admin,
                    security_score, risk_level, total_checks, passed_checks,
                    failed_checks, warn_checks, unknown_checks, error_checks,
                    duration_seconds, hostname, os_name, os_build, privilege_coverage
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.scan_id,
                result.timestamp,
                result.winsecure_version,
                result.profile,
                1 if result.is_admin else 0,
                result.security_score,
                result.risk_level.value,
                metrics.total_checks if metrics else len(result.findings),
                metrics.passed_checks if metrics else 0,
                metrics.failed_checks if metrics else 0,
                metrics.warn_checks if metrics else 0,
                metrics.unknown_checks if metrics else 0,
                metrics.error_checks if metrics else 0,
                metrics.duration_seconds if metrics else 0.0,
                inv.hostname if inv else "Unknown",
                inv.os_name if inv else "Windows",
                inv.os_build if inv else "Unknown",
                metrics.privilege_coverage_percent if metrics else 100.0,
            ))

            # 2. Insert findings & evidence
            for f in result.findings:
                cursor.execute("""
                    INSERT OR REPLACE INTO findings (
                        id, scan_id, title, category, severity, status, confidence,
                        description, expected, actual, impact, remediation, requires_admin, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f.id,
                    result.scan_id,
                    f.title,
                    f.category,
                    f.severity.value,
                    f.status.value,
                    f.confidence,
                    f.description,
                    f.expected,
                    f.actual,
                    f.impact,
                    f.remediation,
                    1 if f.requires_admin else 0,
                    f.timestamp,
                ))

                for ev_dict in f.evidence:
                    cursor.execute("""
                        INSERT OR REPLACE INTO evidence (
                            evidence_id, scan_id, finding_id, source, collector, data_json, command_executed, timestamp
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ev_dict.get("evidence_id"),
                        result.scan_id,
                        f.id,
                        ev_dict.get("source", "Unknown"),
                        ev_dict.get("collector", "Unknown"),
                        json.dumps(ev_dict.get("data"), default=str),
                        ev_dict.get("command_executed"),
                        ev_dict.get("timestamp", result.timestamp),
                    ))

            # 3. Insert compliance assessments
            for summary in result.compliance_summaries:
                for c in summary.controls:
                    cursor.execute("""
                        INSERT INTO compliance_assessments (
                            scan_id, framework, version, control_id, control_title, profile, status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        result.scan_id,
                        summary.framework,
                        summary.version,
                        c.control_id,
                        c.control_title,
                        c.profile,
                        c.status.value,
                    ))

            # 4. Insert remediations
            for r in result.remediations:
                cursor.execute("""
                    INSERT INTO remediations (
                        scan_id, finding_id, title, priority, what_is_wrong,
                        why_it_matters, how_to_fix, powershell_script, validation_command
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.scan_id,
                    r.finding_id,
                    r.title,
                    r.priority.value,
                    r.what_is_wrong,
                    r.why_it_matters,
                    r.how_to_fix,
                    r.powershell_script,
                    r.validation_command,
                ))

            # 5. Insert benchmarks
            if metrics:
                cursor.execute("""
                    INSERT OR REPLACE INTO scan_benchmarks (
                        scan_id, cpu_percent_avg, peak_memory_mb, checks_per_second, duration_seconds
                    ) VALUES (?, ?, ?, ?, ?)
                """, (
                    result.scan_id,
                    metrics.cpu_percent_avg,
                    metrics.peak_memory_mb,
                    metrics.checks_per_second,
                    metrics.duration_seconds,
                ))

            # 6. Insert errors
            for err in result.errors:
                cursor.execute("""
                    INSERT INTO errors (scan_id, module, check_id, error_message, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    result.scan_id,
                    err.get("module", "N/A"),
                    err.get("check_id"),
                    err.get("error", "Unknown error"),
                    err.get("timestamp", result.timestamp),
                ))

            conn.commit()

        # Synchronize staged data to disk
        self.db.sync_to_disk()

    def get_latest_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieves recent scans for benchmarking and history comparison."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
