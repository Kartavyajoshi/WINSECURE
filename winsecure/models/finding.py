"""
WinSecure Finding & Security Test Result Data Model
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from winsecure.models.evidence import Evidence


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

    @property
    def score_weight(self) -> float:
        weights = {
            Severity.CRITICAL: 15.0,
            Severity.HIGH: 10.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.0,
            Severity.INFORMATIONAL: 0.0,
        }
        return weights.get(self, 0.0)

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        val_map = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "informational": cls.INFORMATIONAL,
            "info": cls.INFORMATIONAL,
        }
        return val_map.get(value.lower(), cls.MEDIUM)


class FindingStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"

    @classmethod
    def from_string(cls, value: str) -> "FindingStatus":
        val_map = {
            "pass": cls.PASS,
            "fail": cls.FAIL,
            "warn": cls.WARN,
            "warning": cls.WARN,
            "unknown": cls.UNKNOWN,
            "not_applicable": cls.NOT_APPLICABLE,
            "na": cls.NOT_APPLICABLE,
            "skipped": cls.NOT_APPLICABLE,
            "skip": cls.NOT_APPLICABLE,
            "error": cls.ERROR,
        }
        return val_map.get(value.lower(), cls.UNKNOWN)


@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: Severity
    status: FindingStatus
    confidence: float
    description: str
    expected: str
    actual: str
    impact: str
    remediation: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    compliance: List[Dict[str, str]] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    requires_admin: bool = False
    rationale: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    module: str = "General"
    duration: float = 0.0
    raw_output: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def test_id(self) -> str:
        return self.id

    @property
    def passed(self) -> bool:
        return self.status == FindingStatus.PASS

    @property
    def failed(self) -> bool:
        return self.status == FindingStatus.FAIL

    @property
    def skipped(self) -> bool:
        return self.status == FindingStatus.NOT_APPLICABLE or self.status == FindingStatus.UNKNOWN

    @property
    def is_warn(self) -> bool:
        return self.status == FindingStatus.WARN

    @property
    def is_error(self) -> bool:
        return self.status == FindingStatus.ERROR

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["test_id"] = self.id
        data["severity"] = self.severity.value if isinstance(self.severity, Severity) else str(self.severity)
        data["status"] = self.status.value if isinstance(self.status, FindingStatus) else str(self.status)
        data["passed"] = self.passed
        data["failed"] = self.failed
        data["skipped"] = self.skipped
        data["is_warn"] = self.is_warn
        data["is_error"] = self.is_error
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        sev = data.get("severity", "Medium")
        if isinstance(sev, str):
            sev = Severity.from_string(sev)
        st = data.get("status", "UNKNOWN")
        if isinstance(st, str):
            st = FindingStatus.from_string(st)

        finding_id = data.get("id") or data.get("test_id") or "WIN-GEN-000"

        return cls(
            id=finding_id,
            title=data.get("title", "Untitled Finding"),
            category=data.get("category", "General"),
            severity=sev,
            status=st,
            confidence=float(data.get("confidence", 0.90)),
            description=data.get("description", ""),
            expected=data.get("expected", ""),
            actual=data.get("actual", ""),
            impact=data.get("impact", ""),
            remediation=data.get("remediation", ""),
            evidence=data.get("evidence", []),
            references=data.get("references", []),
            compliance=data.get("compliance", []),
            mitre_attack=data.get("mitre_attack", []),
            requires_admin=data.get("requires_admin", False),
            rationale=data.get("rationale"),
            tags=data.get("tags", []),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            module=data.get("module", data.get("category", "General")),
            duration=float(data.get("duration", 0.0)),
            raw_output=data.get("raw_output"),
            metadata=data.get("metadata", {}),
        )
