"""
WinSecure Remediation Data Model
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class RemediationPriority(str, Enum):
    P0_IMMEDIATE = "P0 - Immediate"
    P1_HIGH = "P1 - 24 Hours"
    P2_MEDIUM = "P2 - 7 Days"
    P3_LOW = "P3 - 30 Days"
    P4_LONG_TERM = "P4 - Long Term / Architectural"

    @classmethod
    def from_severity(cls, severity_str: str) -> "RemediationPriority":
        s = severity_str.lower()
        if "crit" in s:
            return cls.P0_IMMEDIATE
        if "high" in s:
            return cls.P1_HIGH
        if "med" in s:
            return cls.P2_MEDIUM
        if "low" in s:
            return cls.P3_LOW
        return cls.P4_LONG_TERM


@dataclass
class RemediationAction:
    finding_id: str
    title: str
    category: str
    priority: RemediationPriority
    what_is_wrong: str
    why_it_matters: str
    how_to_fix: str
    powershell_script: str
    gpo_or_gui_alternative: Optional[str] = None
    side_effects: str = "None anticipated in standard enterprise environments."
    rollback_guidance: str = "Revert registry value or group policy setting to prior configuration."
    validation_command: str = ""
    estimated_effort_minutes: int = 5
    requires_reboot: bool = False

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["priority"] = self.priority.value if isinstance(self.priority, RemediationPriority) else str(self.priority)
        return data
