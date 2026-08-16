"""
WinSecure Scan Result and Summary Models
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from winsecure.models.finding import Finding
from winsecure.models.module import ScannerHealth
from winsecure.models.compliance import FrameworkSummary
from winsecure.models.remediation import RemediationAction
from winsecure.models.inventory import SystemInventory


class RiskLevel(str, Enum):
    EXCELLENT = "EXCELLENT"  # 90-100
    STRONG = "STRONG"        # 80-89
    MODERATE = "MODERATE"    # 70-79
    WEAK = "WEAK"            # 50-69
    CRITICAL = "CRITICAL"    # 0-49

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        if score >= 90.0:
            return cls.EXCELLENT
        elif score >= 80.0:
            return cls.STRONG
        elif score >= 70.0:
            return cls.MODERATE
        elif score >= 50.0:
            return cls.WEAK
        else:
            return cls.CRITICAL


@dataclass
class ScoreDeduction:
    finding_id: str
    title: str
    category: str
    severity: str
    points_deducted: float
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanMetrics:
    start_time: str
    end_time: str
    duration_seconds: float
    cpu_percent_avg: float = 0.0
    peak_memory_mb: float = 0.0
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    warn_checks: int = 0
    unknown_checks: int = 0
    not_applicable_checks: int = 0
    error_checks: int = 0
    checks_per_second: float = 0.0
    privilege_coverage_percent: float = 100.0
    assessment_coverage_percent: float = 100.0
    accessible_checks_count: int = 0
    restricted_checks_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    scan_id: str
    timestamp: str
    winsecure_version: str
    profile: str
    is_admin: bool
    security_score: float
    risk_level: RiskLevel
    assessment_coverage_percent: float = 100.0
    accessible_checks_count: int = 0
    restricted_checks_count: int = 0
    score_deductions: List[ScoreDeduction] = field(default_factory=list)
    metrics: Optional[ScanMetrics] = None
    inventory: Optional[SystemInventory] = None
    findings: List[Finding] = field(default_factory=list)
    scanner_health: List[ScannerHealth] = field(default_factory=list)
    compliance_summaries: List[FrameworkSummary] = field(default_factory=list)
    remediations: List[RemediationAction] = field(default_factory=list)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    ai_insights: Dict[str, Any] = field(default_factory=dict)
    comparison_data: Dict[str, Any] = field(default_factory=dict)
    drift_data: Dict[str, Any] = field(default_factory=dict)
    executive_summary: str = ""
    errors: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "winsecure_version": self.winsecure_version,
            "profile": self.profile,
            "is_admin": self.is_admin,
            "security_score": self.security_score,
            "risk_level": self.risk_level.value if isinstance(self.risk_level, RiskLevel) else str(self.risk_level),
            "assessment_coverage_percent": self.assessment_coverage_percent,
            "accessible_checks_count": self.accessible_checks_count,
            "restricted_checks_count": self.restricted_checks_count,
            "score_deductions": [d.to_dict() for d in self.score_deductions],
            "metrics": self.metrics.to_dict() if self.metrics else {},
            "inventory": self.inventory.to_dict() if self.inventory else {},
            "findings": [f.to_dict() for f in self.findings],
            "scanner_health": [s.to_dict() for s in self.scanner_health],
            "compliance_summaries": [c.to_dict() for c in self.compliance_summaries],
            "remediations": [r.to_dict() for r in self.remediations],
            "anomalies": self.anomalies,
            "ai_insights": self.ai_insights,
            "comparison_data": self.comparison_data,
            "drift_data": self.drift_data,
            "executive_summary": self.executive_summary,
            "errors": self.errors,
        }
