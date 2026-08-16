"""
WinSecure Tool Comparison Data Models
"""
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


@dataclass
class ToolFeatureEvaluation:
    tool_name: str
    category: str
    score: float  # 0 to 10
    has_feature: bool
    details: str


@dataclass
class ToolComparisonProfile:
    id: str
    name: str
    type: str  # "Defensive Platform", "GUI Utility", "Offensive Script", "AD Auditor", "SCAP Engine"
    developer: str
    primary_focus: str
    license: str
    execution_simplicity: str  # "One Command", "Multi-step", "Complex XML", "GUI Only"
    defensive_safety: str      # "Safe (Read-Only)", "Modifies System", "Noisy / Offensive"
    compliance_mappings: List[str]
    risk_scoring_model: str
    evidence_handling: str
    reporting_formats: List[str]
    windows_domains_covered: int
    strengths: List[str]
    limitations: List[str]
    dimension_scores: Dict[str, float]  # Dimensions: Architecture, Coverage, Compliance, Scoring, Evidence, Reporting, Safety, UX

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
