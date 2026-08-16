"""
WinSecure Rule Definition Model
"""
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
from winsecure.models.finding import Severity


@dataclass
class Rule:
    id: str
    title: str
    category: str
    severity: Severity
    description: str
    expected: str
    impact: str
    remediation_guidance: str
    check_type: str = "registry"  # registry, powershell, wmi, auditpol, service, secedit, netsh, config
    check_params: Dict[str, Any] = field(default_factory=dict)
    compliance_mappings: List[Dict[str, str]] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    requires_admin: bool = False
    supported_os: List[str] = field(default_factory=lambda: ["Windows 10", "Windows 11", "Windows Server"])
    tags: List[str] = field(default_factory=list)
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value if isinstance(self.severity, Severity) else str(self.severity)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Rule":
        sev = data.get("severity", "Medium")
        if isinstance(sev, str):
            sev = Severity.from_string(sev)
        return cls(
            id=data["id"],
            title=data.get("title", ""),
            category=data.get("category", "General"),
            severity=sev,
            description=data.get("description", ""),
            expected=data.get("expected", ""),
            impact=data.get("impact", ""),
            remediation_guidance=data.get("remediation_guidance", ""),
            check_type=data.get("check_type", "registry"),
            check_params=data.get("check_params", {}),
            compliance_mappings=data.get("compliance_mappings", []),
            mitre_attack=data.get("mitre_attack", []),
            references=data.get("references", []),
            requires_admin=data.get("requires_admin", False),
            supported_os=data.get("supported_os", ["Windows 10", "Windows 11", "Windows Server"]),
            tags=data.get("tags", []),
            enabled=data.get("enabled", True),
        )
