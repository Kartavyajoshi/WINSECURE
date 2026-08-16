"""
WinSecure Compliance Assessment Engine
"""
import glob
import json
import os
from typing import Dict, List, Optional
from winsecure.models.finding import Finding, FindingStatus
from winsecure.models.compliance import (
    ComplianceControl,
    ControlAssessment,
    FrameworkSummary,
    ComplianceStatus,
)


class ComplianceEngine:
    """Evaluates scan findings against mapped compliance framework benchmarks."""

    def __init__(self, benchmarks_dir: Optional[str] = None):
        if not benchmarks_dir:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            benchmarks_dir = os.path.join(base_dir, "benchmarks")
        self.benchmarks_dir = benchmarks_dir
        self.controls: Dict[str, List[ComplianceControl]] = self._load_benchmarks()

    def _load_benchmarks(self) -> Dict[str, List[ComplianceControl]]:
        framework_controls = {}
        if not os.path.exists(self.benchmarks_dir):
            return framework_controls

        for fpath in sorted(glob.glob(os.path.join(self.benchmarks_dir, "*.json"))):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    fw_name = data.get("framework", "Unknown")
                    fw_ver = data.get("version", "1.0")
                    ctrl_list = []
                    for item in data.get("controls", []):
                        ctrl = ComplianceControl(
                            framework=fw_name,
                            framework_version=fw_ver,
                            control_id=item.get("id", ""),
                            control_title=item.get("title", ""),
                            description=item.get("description", ""),
                            profile=item.get("profile", "Level 1"),
                            reference_url=item.get("url"),
                            mapped_rules=item.get("rules", []),
                        )
                        ctrl_list.append(ctrl)
                    framework_controls[fw_name] = ctrl_list
            except Exception:
                pass
        return framework_controls

    def evaluate(self, findings: List[Finding]) -> List[FrameworkSummary]:
        """Maps findings to compliance controls and calculates scores per framework."""
        finding_map = {f.id: f for f in findings}
        summaries = []

        for fw_name, ctrl_list in self.controls.items():
            version = ctrl_list[0].framework_version if ctrl_list else "1.0"
            summary = FrameworkSummary(framework=fw_name, version=version)

            for ctrl in ctrl_list:
                assessment = ControlAssessment(
                    framework=fw_name,
                    control_id=ctrl.control_id,
                    control_title=ctrl.control_title,
                    profile=ctrl.profile,
                    status=ComplianceStatus.PASS,
                )

                if not ctrl.mapped_rules:
                    assessment.status = ComplianceStatus.UNKNOWN
                else:
                    mapped_findings = [finding_map.get(r_id) for r_id in ctrl.mapped_rules if r_id in finding_map]
                    
                    if not mapped_findings:
                        assessment.status = ComplianceStatus.UNKNOWN
                    else:
                        statuses = [f.status for f in mapped_findings]
                        if any(s == FindingStatus.FAIL for s in statuses):
                            assessment.status = ComplianceStatus.FAIL
                            assessment.failing_rules = [f.id for f in mapped_findings if f.status == FindingStatus.FAIL]
                        elif any(s == FindingStatus.WARN for s in statuses):
                            assessment.status = ComplianceStatus.PARTIAL
                            assessment.warning_rules = [f.id for f in mapped_findings if f.status == FindingStatus.WARN]
                        elif all(s == FindingStatus.PASS for s in statuses):
                            assessment.status = ComplianceStatus.PASS
                            assessment.passing_rules = [f.id for f in mapped_findings if f.status == FindingStatus.PASS]
                        elif all(s == FindingStatus.NOT_APPLICABLE for s in statuses):
                            assessment.status = ComplianceStatus.NOT_APPLICABLE
                        else:
                            assessment.status = ComplianceStatus.PARTIAL

                summary.controls.append(assessment)

            summary.calculate()
            summaries.append(summary)

        return summaries
