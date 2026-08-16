"""
WinSecure Transparent Risk Scoring Engine
"""
from typing import List, Tuple
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.scan import RiskLevel, ScoreDeduction


class RiskEngine:
    """
    Calculates a transparent, explainable 0-100 Security Risk Score.
    Every deduction is tracked with exact point values and reasons.
    """

    BASE_SCORE: float = 100.0

    # Severity base penalties
    SEVERITY_PENALTIES = {
        Severity.CRITICAL: 15.0,
        Severity.HIGH: 10.0,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.0,
        Severity.INFORMATIONAL: 0.0,
    }

    # Category impact multipliers
    CATEGORY_WEIGHTS = {
        "Defender": 1.2,
        "Firewall": 1.2,
        "UAC": 1.15,
        "SMB": 1.15,
        "Remote Access": 1.1,
        "Registry": 1.05,
        "Audit Policy": 1.0,
        "Encryption": 1.0,
        "Accounts": 1.0,
        "PowerShell": 0.95,
        "System": 0.95,
        "Event Logs": 0.9,
        "Network": 0.9,
        "Updates": 0.9,
        "Installed Software": 0.85,
        "Scheduled Tasks": 0.85,
        "Startup": 0.85,
        "Services": 0.85,
        "SmartScreen": 0.8,
        "Privileges": 0.8,
    }

    @classmethod
    def calculate_score(cls, findings: List[Finding]) -> Tuple[float, RiskLevel, List[ScoreDeduction]]:
        """
        Computes overall score from failing and warning findings.
        Returns: (final_score, risk_level, deductions_list)
        """
        current_score = cls.BASE_SCORE
        deductions: List[ScoreDeduction] = []

        for f in findings:
            if f.status == FindingStatus.FAIL:
                base_pen = cls.SEVERITY_PENALTIES.get(f.severity, 5.0)
                cat_weight = cls.CATEGORY_WEIGHTS.get(f.category, 1.0)
                # Scale by confidence factor (0.5 to 1.0)
                conf_factor = max(0.5, min(1.0, f.confidence))
                points = round(base_pen * cat_weight * conf_factor, 1)

                deduction = ScoreDeduction(
                    finding_id=f.id,
                    title=f.title,
                    category=f.category,
                    severity=f.severity.value,
                    points_deducted=points,
                    reason=f"{f.severity.value} security defect in {f.category} ({f.actual})",
                )
                deductions.append(deduction)
                current_score -= points

            elif f.status == FindingStatus.WARN:
                base_pen = cls.SEVERITY_PENALTIES.get(f.severity, 5.0) * 0.4
                cat_weight = cls.CATEGORY_WEIGHTS.get(f.category, 1.0)
                points = round(base_pen * cat_weight * f.confidence, 1)

                deduction = ScoreDeduction(
                    finding_id=f.id,
                    title=f.title,
                    category=f.category,
                    severity="Warning",
                    points_deducted=points,
                    reason=f"Suboptimal configuration warning in {f.category}",
                )
                deductions.append(deduction)
                current_score -= points

        final_score = max(0.0, min(100.0, round(current_score, 1)))
        risk_level = RiskLevel.from_score(final_score)

        # Sort deductions by point impact descending
        deductions.sort(key=lambda d: d.points_deducted, reverse=True)

        return final_score, risk_level, deductions
