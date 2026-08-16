"""
WinSecure Markdown Audit Report Generator
"""
import os
from datetime import datetime, timezone
from typing import List
from winsecure.models.scan import ScanResult
from winsecure.models.finding import FindingStatus, Severity


class MarkdownExporter:
    """Generates clean, professional GitHub Flavored Markdown audit reports."""

    @staticmethod
    def export(result: ScanResult, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir, "report.md")

        inv = result.inventory
        hostname = inv.hostname if inv else "Local Host"
        os_name = inv.os_name if inv else "Windows 11"
        os_arch = inv.os_architecture if inv else "x64"
        duration_str = f"{result.metrics.duration_seconds:.2f}s" if result.metrics else "N/A"

        crit_count = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.HIGH)
        med_count = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.LOW)
        pass_count = sum(1 for f in result.findings if f.status == FindingStatus.PASS)
        warn_count = sum(1 for f in result.findings if f.status == FindingStatus.WARN)
        unknown_count = sum(1 for f in result.findings if f.status == FindingStatus.UNKNOWN)
        total_checks = len(result.findings)

        failing_findings = [f for f in result.findings if f.status == FindingStatus.FAIL]
        passed_findings = [f for f in result.findings if f.status == FindingStatus.PASS]
        warn_findings = [f for f in result.findings if f.status == FindingStatus.WARN]
        unknown_findings = [f for f in result.findings if f.status in (FindingStatus.UNKNOWN, FindingStatus.NOT_APPLICABLE)]

        md = []
        md.append(f"# WinSecure Security Assessment Report")
        md.append(f"**Scan ID:** `{result.scan_id}` | **Target:** `{hostname}` | **Date:** `{result.timestamp}` | **Version:** `v{result.winsecure_version}`\n")

        md.append("## 1. Executive Summary\n")
        md.append(f"- **Overall Defensive Posture Score:** **`{result.security_score:.1f} / 100`** ({result.risk_level.value if hasattr(result.risk_level, 'value') else result.risk_level})")
        md.append(f"- **Target Endpoint:** `{hostname}` ({os_name} {os_arch})")
        md.append(f"- **Execution Privilege:** `{'Administrator (Elevated)' if result.is_admin else 'Standard User'}`")
        md.append(f"- **Scan Duration:** `{duration_str}`")
        md.append(f"- **Total Evaluated Controls:** `{total_checks}` (Passed: `{pass_count}`, Failed: `{len(failing_findings)}`, Warnings: `{warn_count}`, Restricted/Skipped: `{unknown_count}`)\n")

        md.append("## 2. Risk Distribution\n")
        md.append("| Severity Level | Count | Status |")
        md.append("| :--- | :--- | :--- |")
        md.append(f"| **CRITICAL** | `{crit_count}` | {'🔴 Immediate Action Required' if crit_count > 0 else '🟢 None'} |")
        md.append(f"| **HIGH** | `{high_count}` | {'🟠 High Exposure' if high_count > 0 else '🟢 None'} |")
        md.append(f"| **MEDIUM** | `{med_count}` | {'🟡 Suboptimal' if med_count > 0 else '🟢 None'} |")
        md.append(f"| **LOW** | `{low_count}` | {'🔵 Informational' if low_count > 0 else '🟢 None'} |")
        md.append(f"| **PASSED** | `{pass_count}` | 🟢 Compliant |")
        md.append(f"| **WARNINGS** | `{warn_count}` | 🟡 Review Recommended |\n")

        md.append("## 3. Failed Misconfigurations (Action Required)\n")
        if not failing_findings:
            md.append("✅ **No failing security misconfigurations identified.**\n")
        else:
            for i, f in enumerate(failing_findings, 1):
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                md.append(f"### {i}. [{f.id}] {f.title}")
                md.append(f"- **Category:** `{f.category}` | **Severity:** `{sev.upper()}`")
                md.append(f"- **Description:** {f.description}")
                md.append(f"- **Expected Configuration:** `{f.expected}`")
                md.append(f"- **Actual State:** `{f.actual}`")
                md.append(f"- **Security Impact:** {f.impact}")
                md.append(f"- **PowerShell Remediation:**\n```powershell\n{f.remediation}\n```")
                if f.compliance:
                    comp_str = ", ".join(f"{c.get('framework', '')} {c.get('control_id', '')}".strip() for c in f.compliance if isinstance(c, dict))
                    if comp_str:
                        md.append(f"- **Compliance Alignment:** `{comp_str}`")
                md.append("")

        md.append("## 4. Warnings & Review Items\n")
        if not warn_findings:
            md.append("No configuration warnings recorded.\n")
        else:
            for w in warn_findings:
                md.append(f"- **[{w.id}] {w.title}**: {w.actual} *(Impact: {w.impact})*")
            md.append("")

        md.append("## 5. Verified Compliant Controls\n")
        md.append(f"Total verified baseline controls: **{len(passed_findings)}**\n")
        for p in passed_findings:
            md.append(f"- `[PASS]` **[{p.id}]** {p.title} (`{p.category}`)")

        md.append("\n---\n*Report generated automatically by WinSecure Cybersecurity Platform.*")

        content = "\n".join(md)
        with open(report_path, "w", encoding="utf-8") as file:
            file.write(content)

        return report_path
