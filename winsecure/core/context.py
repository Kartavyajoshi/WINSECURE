"""
WinSecure Scan Execution Context
"""
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from winsecure.core.config import ScanConfig
from winsecure.models.finding import Finding
from winsecure.models.evidence import Evidence
from winsecure.models.compliance import FrameworkSummary
from winsecure.models.remediation import RemediationAction
from winsecure.models.inventory import SystemInventory
from winsecure.models.scan import ScanMetrics, RiskLevel, ScoreDeduction


@dataclass
class ScanContext:
    config: ScanConfig
    scan_id: str = field(default_factory=lambda: f"SCAN-{uuid.uuid4().hex[:8].upper()}")
    start_time_iso: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    start_perf_time: float = field(default_factory=time.perf_counter)
    
    # Environment info
    is_windows: bool = False
    is_admin: bool = False
    os_info: Dict[str, Any] = field(default_factory=dict)
    privilege_coverage_percent: float = 100.0
    
    # Collected artifacts store
    collected_artifacts: Dict[str, Any] = field(default_factory=dict)
    
    # Analysis outputs
    inventory: Optional[SystemInventory] = None
    findings: List[Finding] = field(default_factory=list)
    compliance_summaries: List[FrameworkSummary] = field(default_factory=list)
    remediations: List[RemediationAction] = field(default_factory=list)
    score_deductions: List[ScoreDeduction] = field(default_factory=list)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    ai_insights: Dict[str, Any] = field(default_factory=dict)
    executive_summary: str = ""
    errors: List[Dict[str, str]] = field(default_factory=list)
    
    # Calculated scores
    security_score: float = 100.0
    risk_level: RiskLevel = RiskLevel.EXCELLENT
    metrics: Optional[ScanMetrics] = None

    def add_error(self, module: str, error_msg: str, check_id: Optional[str] = None) -> None:
        self.errors.append({
            "module": module,
            "error": error_msg,
            "check_id": check_id or "N/A",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
