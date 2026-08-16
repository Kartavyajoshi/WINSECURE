"""
WinSecure Compliance Models
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class ComplianceStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class ComplianceControl:
    framework: str          # e.g., "CIS Windows 11 Enterprise", "NIST SP 800-53"
    framework_version: str  # e.g., "5.0.1", "Rev 5"
    control_id: str         # e.g., "1.1.1", "AC-2"
    control_title: str      # Internally-authored concise title
    description: str        # Internally-authored description
    profile: str = "Level 1"  # Level 1, Level 2, Moderate, High, etc.
    reference_url: Optional[str] = None
    mapped_rules: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ControlAssessment:
    framework: str
    control_id: str
    control_title: str
    profile: str
    status: ComplianceStatus
    passing_rules: List[str] = field(default_factory=list)
    failing_rules: List[str] = field(default_factory=list)
    warning_rules: List[str] = field(default_factory=list)
    unknown_rules: List[str] = field(default_factory=list)
    not_applicable_rules: List[str] = field(default_factory=list)
    evidence_summary: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value if isinstance(self.status, ComplianceStatus) else str(self.status)
        return data


@dataclass
class FrameworkSummary:
    framework: str
    version: str
    total_controls: int = 0
    passed: int = 0
    failed: int = 0
    partial: int = 0
    not_applicable: int = 0
    unknown: int = 0
    compliance_percentage: float = 0.0
    controls: List[ControlAssessment] = field(default_factory=list)

    def calculate(self) -> None:
        self.total_controls = len(self.controls)
        self.passed = sum(1 for c in self.controls if c.status == ComplianceStatus.PASS)
        self.failed = sum(1 for c in self.controls if c.status == ComplianceStatus.FAIL)
        self.partial = sum(1 for c in self.controls if c.status == ComplianceStatus.PARTIAL)
        self.not_applicable = sum(1 for c in self.controls if c.status == ComplianceStatus.NOT_APPLICABLE)
        self.unknown = sum(1 for c in self.controls if c.status == ComplianceStatus.UNKNOWN)
        
        evaluable = self.passed + self.failed + self.partial
        if evaluable > 0:
            # Partial gets 50% credit
            effective_pass = self.passed + (0.5 * self.partial)
            self.compliance_percentage = round((effective_pass / evaluable) * 100.0, 1)
        else:
            self.compliance_percentage = 100.0 if self.total_controls > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework": self.framework,
            "version": self.version,
            "total_controls": self.total_controls,
            "passed": self.passed,
            "failed": self.failed,
            "partial": self.partial,
            "not_applicable": self.not_applicable,
            "unknown": self.unknown,
            "compliance_percentage": self.compliance_percentage,
            "controls": [c.to_dict() for c in self.controls],
        }
