"""
WinSecure Master Report Generator Orchestrator
"""
import os
from winsecure.models.scan import ScanResult
from winsecure.reporting.json_exporter import JsonExporter
from winsecure.reporting.csv_exporter import CsvExporter
from winsecure.reporting.sarif_exporter import SarifExporter
from winsecure.reporting.mitre_exporter import MitreAttackExporter
from winsecure.reporting.markdown_exporter import MarkdownExporter
from winsecure.reporting.web_generator import WebReportGenerator
from winsecure.reporting.executive_report import ExecutiveReportGenerator
from winsecure.reporting.technical_report import TechnicalReportGenerator


class ReportGenerator:
    """Coordinates the generation of JSON, CSV, SARIF, Markdown, Executive, Technical, and Web Reports."""

    @staticmethod
    def generate_all(result: ScanResult, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)

        # 1. Machine JSON Telemetry
        JsonExporter.export_all(result, output_dir)

        # 2. CSV Finding Matrix
        CsvExporter.export_findings(result, output_dir)

        # 3. SARIF Export (for GitHub Security / CI/CD)
        SarifExporter.export(result, output_dir)

        # 4. MITRE ATT&CK Matrix Export
        MitreAttackExporter.export(result, output_dir)

        # 5. Markdown Audit Summary
        MarkdownExporter.export(result, output_dir)

        # 6. Standalone Executive & Technical HTML Reports
        ExecutiveReportGenerator.generate(result, output_dir)
        TechnicalReportGenerator.generate(result, output_dir)

        # 7. Master Interactive Web Report Dashboard
        index_path = WebReportGenerator.generate(result, output_dir)

        return index_path
