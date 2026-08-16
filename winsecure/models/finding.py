"""
WinSecure Finding Data Model
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

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value if isinstance(self.severity, Severity) else str(self.severity)
        data["status"] = self.status.value if isinstance(self.status, FindingStatus) else str(self.status)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        sev = data.get("severity", "Medium")
        if isinstance(sev, str):
            sev = Severity.from_string(sev)
        st = data.get("status", "UNKNOWN")
        if isinstance(st, str):
            st = FindingStatus.from_string(st)

        return cls(
            id=data.get("id", "WIN-GEN-000"),
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
        )
