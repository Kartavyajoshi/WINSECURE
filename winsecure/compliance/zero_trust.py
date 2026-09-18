"""
WinSecure CISA Zero Trust Maturity Model (ZTMM v2.0) Device Pillar Evaluator
Grounded in:
- NIST SP 800-207: "Zero Trust Architecture" (2020)
- Cybersecurity and Infrastructure Security Agency (CISA): "Zero Trust Maturity Model Version 2.0" (Device Pillar, 2023)
"""
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any, Dict, List, Set
from winsecure.models.finding import Finding, FindingStatus


class ZeroTrustStage(str, Enum):
    TRADITIONAL = "TRADITIONAL"
    INITIAL = "INITIAL"
    ADVANCED = "ADVANCED"
    OPTIMAL = "OPTIMAL"


@dataclass
class ZeroTrustDimension:
    id: str
    name: str
    weight: float
    score: float  # 0 to 100
    description: str
    required_controls: List[str]
    passing_controls: List[str]
    failing_controls: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ZeroTrustEvaluator:
    """
    Evaluates host security posture against the CISA Zero Trust Maturity Model
    Version 2.0 (Device Pillar), determining maturity stage and gap remediation.
    """

    @classmethod
    def evaluate(cls, findings: List[Finding]) -> Dict[str, Any]:
        passing_ids: Set[str] = {f.id for f in findings if f.status == FindingStatus.PASS}
        failing_ids: Set[str] = {f.id for f in findings if f.status in (FindingStatus.FAIL, FindingStatus.WARN)}

        dimensions_def = [
            {
                "id": "hardware_root_of_trust",
                "name": "Hardware & Firmware Root of Trust",
                "weight": 20.0,
                "description": "TPM 2.0, Secure Boot, Kernel DMA, and hardware-enforced integrity verification.",
                "controls": ["WS-SYS-001", "WS-SYS-002", "WS-CET-001"],
            },
            {
                "id": "device_health_integrity",
                "name": "Device Health & Code Integrity",
                "weight": 25.0,
                "description": "Virtualization-Based Security (VBS), HVCI, and application execution allowlists.",
                "controls": ["WS-VBS-001", "WS-APP-001", "WS-LOL-001", "WS-EXP-001"],
            },
            {
                "id": "credential_hygiene",
                "name": "Credential Isolation & Identity Defense",
                "weight": 20.0,
                "description": "LSA RunAsPPL, Credential Guard, Windows LAPS, and WDigest plaintext caching denial.",
                "controls": ["WS-REG-001", "WS-REG-002", "WS-LAPS-001", "WS-CG-001"],
            },
            {
                "id": "network_microsegmentation",
                "name": "Network Boundary & Micro-segmentation",
                "weight": 15.0,
                "description": "Host-based firewall default-inbound deny, SMB packet signing, and broadcast protocol deprecation.",
                "controls": ["WS-FW-001", "WS-FW-002", "WS-FW-004", "WS-SMB-002", "WS-NET-001"],
            },
            {
                "id": "visibility_and_telemetry",
                "name": "Continuous Telemetry & Real-Time Monitoring",
                "weight": 20.0,
                "description": "Process command-line auditing, PowerShell ScriptBlock logging, and Defender Real-Time heuristics.",
                "controls": ["WS-DEF-001", "WS-DEF-002", "WS-PS-001", "WS-AUD-001", "WS-SYS-003"],
            },
        ]

        dimension_results: List[ZeroTrustDimension] = []
        weighted_scores_sum = 0.0
        total_weights = 0.0

        for d_def in dimensions_def:
            ctrls = d_def["controls"]
            pass_c = [c for c in ctrls if c in passing_ids]
            fail_c = [c for c in ctrls if c in failing_ids]
            # Controls not tested or passing by default get 75% credit if not failing
            untested_c = [c for c in ctrls if c not in passing_ids and c not in failing_ids]
            
            # Score formula: passing count + 0.5 * untested / total
            dim_score = round(((len(pass_c) + 0.7 * len(untested_c)) / max(1, len(ctrls))) * 100.0, 1)
            dim_score = min(100.0, max(0.0, dim_score))

            dim_obj = ZeroTrustDimension(
                id=d_def["id"],
                name=d_def["name"],
                weight=d_def["weight"],
                score=dim_score,
                description=d_def["description"],
                required_controls=ctrls,
                passing_controls=pass_c,
                failing_controls=fail_c,
            )
            dimension_results.append(dim_obj)
            weighted_scores_sum += dim_score * d_def["weight"]
            total_weights += d_def["weight"]

        overall_maturity_pct = round(weighted_scores_sum / max(1.0, total_weights), 1)

        # Map to CISA ZTMM Stages
        if overall_maturity_pct >= 85.0:
            stage = ZeroTrustStage.OPTIMAL
            stage_desc = "Optimal Stage: Fully automated device health attestation, hardware root of trust, and continuous dynamic policy enforcement."
        elif overall_maturity_pct >= 70.0:
            stage = ZeroTrustStage.ADVANCED
            stage_desc = "Advanced Stage: Verified device compliance telemetry, virtualization security, and strict credential isolation."
        elif overall_maturity_pct >= 50.0:
            stage = ZeroTrustStage.INITIAL
            stage_desc = "Initial Stage: Preliminary baseline controls, partial software inventory, and fragmented endpoint protections."
        else:
            stage = ZeroTrustStage.TRADITIONAL
            stage_desc = "Traditional Stage: Perimeter-dependent architecture, unverified local endpoint configurations, high implicit trust."

        # Compute Gaps to Next Stage
        gaps: List[Dict[str, str]] = []
        for d in dimension_results:
            for f_id in d.failing_controls:
                gaps.append({
                    "dimension": d.name,
                    "control_id": f_id,
                    "remediation": f"Harden {f_id} to satisfy CISA ZTMM requirements in {d.name}."
                })

        return {
            "overall_stage": stage.value,
            "overall_maturity_percent": overall_maturity_pct,
            "stage_description": stage_desc,
            "dimensions": [d.to_dict() for d in dimension_results],
            "gaps_count": len(gaps),
            "key_gaps": gaps[:6],
            "framework_version": "CISA ZTMM v2.0 (Device Pillar)",
            "standards_reference": "NIST SP 800-207 Zero Trust Architecture"
        }
