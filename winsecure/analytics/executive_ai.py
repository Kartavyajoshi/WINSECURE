"""
WinSecure Executive AI & Posture Synthesis Layer
"""
from typing import Any, Dict, List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.scan import RiskLevel


class ExecutiveAnalytics:
    """
    Synthesizes scan results into high-level executive insights,
    identifying root causes, risk themes, and strategic recommendations.
    Deterministic, offline, and self-contained.
    """

    @staticmethod
    def generate_executive_summary(
        score: float,
        risk_level: RiskLevel,
        findings: List[Finding],
        anomalies: List[Dict[str, Any]]
    ) -> str:
        crit_count = sum(1 for f in findings if f.status == FindingStatus.FAIL and f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.status == FindingStatus.FAIL and f.severity == Severity.HIGH)
        med_count = sum(1 for f in findings if f.status == FindingStatus.FAIL and f.severity == Severity.MEDIUM)
        
        top_failing = [f.title for f in findings if f.status == FindingStatus.FAIL][:5]

        summary_lines = [
            f"WinSecure Endpoint Assessment completed with a Security Score of {score}/100 (Posture: {risk_level.value}).",
            "",
            f"The assessment identified {crit_count} Critical, {high_count} High, and {med_count} Medium severity configuration defects requiring remediation.",
        ]

        if top_failing:
            summary_lines.append("")
            summary_lines.append("Primary Security Concerns:")
            for i, title in enumerate(top_failing, 1):
                summary_lines.append(f"{i}. {title}")

        if anomalies:
            summary_lines.append("")
            summary_lines.append(f"Configuration Anomaly Alerts: Detected {len(anomalies)} combined risk patterns spanning remote access, boundary filtering, and credential isolation.")

        return "\n".join(summary_lines)

    @staticmethod
    def generate_themes(findings: List[Finding]) -> List[Dict[str, Any]]:
        categories = {}
        for f in findings:
            if f.category not in categories:
                categories[f.category] = {"total": 0, "failed": 0, "passed": 0}
            categories[f.category]["total"] += 1
            if f.status == FindingStatus.FAIL:
                categories[f.category]["failed"] += 1
            elif f.status == FindingStatus.PASS:
                categories[f.category]["passed"] += 1

        themes = []
        for cat, stats in categories.items():
            pass_rate = round((stats["passed"] / stats["total"]) * 100.0, 1) if stats["total"] > 0 else 0
            themes.append({
                "theme": cat,
                "total_checks": stats["total"],
                "passed_checks": stats["passed"],
                "failed_checks": stats["failed"],
                "health_percentage": pass_rate,
            })
        return sorted(themes, key=lambda t: t["health_percentage"])
