"""
WinSecure CSV Exporters
"""
import csv
import os
from winsecure.models.scan import ScanResult


class CsvExporter:
    """Exports findings and compliance metrics into CSV spreadsheets."""

    @staticmethod
    def export_findings(result: ScanResult, output_dir: str) -> str:
        csv_path = os.path.join(output_dir, "findings.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Finding ID", "Title", "Category", "Severity", "Status",
                "Confidence", "Expected", "Actual", "Impact", "Remediation", "Timestamp"
            ])
            for item in result.findings:
                writer.writerow([
                    item.id,
                    item.title,
                    item.category,
                    item.severity.value,
                    item.status.value,
                    item.confidence,
                    item.expected,
                    item.actual,
                    item.impact,
                    item.remediation,
                    item.timestamp,
                ])
        return csv_path
