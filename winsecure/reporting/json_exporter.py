"""
WinSecure JSON Exporters
"""
import json
import os
from winsecure.models.scan import ScanResult


class JsonExporter:
    """Exports structured JSON artifacts into the report data directory."""

    @staticmethod
    def export_all(result: ScanResult, output_dir: str) -> None:
        data_dir = os.path.join(output_dir, "data")
        os.makedirs(data_dir, exist_ok=True)

        # 1. findings.json
        findings_path = os.path.join(data_dir, "findings.json")
        with open(findings_path, "w", encoding="utf-8") as f:
            json.dump([f.to_dict() for f in result.findings], f, indent=2)

        # 2. summary.json
        summary_path = os.path.join(data_dir, "summary.json")
        summary_dict = {
            "scan_id": result.scan_id,
            "timestamp": result.timestamp,
            "winsecure_version": result.winsecure_version,
            "profile": result.profile,
            "is_admin": result.is_admin,
            "security_score": result.security_score,
            "risk_level": result.risk_level.value,
            "assessment_coverage_percent": result.assessment_coverage_percent,
            "accessible_checks_count": result.accessible_checks_count,
            "restricted_checks_count": result.restricted_checks_count,
            "metrics": result.metrics.to_dict() if result.metrics else {},
            "executive_summary": result.executive_summary,
            "score_deductions": [d.to_dict() for d in result.score_deductions],
            "anomalies": result.anomalies,
            "ai_insights": result.ai_insights,
            "drift_data": result.drift_data,
            "errors_count": len(result.errors),
        }
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_dict, f, indent=2)

        # 3. compliance.json
        compliance_path = os.path.join(data_dir, "compliance.json")
        with open(compliance_path, "w", encoding="utf-8") as f:
            json.dump([c.to_dict() for c in result.compliance_summaries], f, indent=2)

        # 4. inventory.json
        inventory_path = os.path.join(data_dir, "inventory.json")
        with open(inventory_path, "w", encoding="utf-8") as f:
            json.dump(result.inventory.to_dict() if result.inventory else {}, f, indent=2)

        # 5. comparison.json
        comparison_path = os.path.join(data_dir, "comparison.json")
        with open(comparison_path, "w", encoding="utf-8") as f:
            json.dump(result.comparison_data, f, indent=2)

        # 6. scanner_health.json
        health_path = os.path.join(data_dir, "scanner_health.json")
        with open(health_path, "w", encoding="utf-8") as f:
            json.dump([s.to_dict() for s in result.scanner_health], f, indent=2)

        # 7. benchmark.json
        benchmark_path = os.path.join(data_dir, "benchmark.json")
        bench_dict = {
            "metrics": result.metrics.to_dict() if result.metrics else {},
            "module_performance": [
                {
                    "module": s.name,
                    "scanner_id": s.scanner_id,
                    "execution_time_ms": s.execution_time_ms,
                    "checks": s.checks_count,
                    "coverage_percent": s.coverage_percent,
                    "status": s.status
                }
                for s in result.scanner_health
            ]
        }
        with open(benchmark_path, "w", encoding="utf-8") as f:
            json.dump(bench_dict, f, indent=2)

        # 8. scan_result.json (Complete bundle)
        full_path = os.path.join(output_dir, "scan_result.json")
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)
