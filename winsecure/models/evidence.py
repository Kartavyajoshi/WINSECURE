"""
WinSecure Evidence Data Model
"""
import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class Evidence:
    source: str
    collector: str
    data: Any
    command_executed: Optional[str] = None
    sanitized: bool = True
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notes: Optional[str] = None
    evidence_id: Optional[str] = None

    def __post_init__(self):
        if not self.evidence_id:
            payload = f"{self.source}:{self.collector}:{json.dumps(self.data, sort_keys=True, default=str)}"
            self.evidence_id = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        return cls(
            source=data.get("source", "Unknown"),
            collector=data.get("collector", "Unknown"),
            data=data.get("data"),
            command_executed=data.get("command_executed"),
            sanitized=data.get("sanitized", True),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            notes=data.get("notes"),
            evidence_id=data.get("evidence_id"),
        )
