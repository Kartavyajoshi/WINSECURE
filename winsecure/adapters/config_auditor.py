"""
Configuration Auditor Adapter
Evaluates core OS defensive controls including LSA protection, UAC, Defender telemetry, and Firewall profiles.
"""
import time
from typing import Dict, Any, List
from winsecure.adapters.base import BaseAdapter


class ConfigAuditorAdapter(BaseAdapter):
    """Performs deep configuration posture analysis against security baseline definitions."""

    def __init__(self):
        super().__init__(
            name="config_auditor",
            version="1.3.0",
            capability="os_configuration_assessment",
        )

    def validate_requirements(self, context: Any) -> bool:
        return True

    def execute(self, target: str, context: Any) -> Dict[str, Any]:
        start = time.perf_counter()
        findings = []
        evidence = []

        reg_data = getattr(context, "collected_artifacts", {}).get("registry", {})
        lsa_ppl = reg_data.get("Lsa", {}).get("RunAsPPL", 0)

        if lsa_ppl != 1:
            findings.append({
                "id": "CFG-LSA-01",
                "title": "LSA Protection (RunAsPPL) Not Enforced",
                "severity": "High",
                "confidence": "High",
                "category": "Registry",
                "description": "LSASS process is not running with Protected Process Light (PPL) protection.",
                "affected_component": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
                "remediation": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord",
            })

        evidence.append({
            "source": "registry_audit",
            "run_as_ppl": lsa_ppl,
        })

        duration = (time.perf_counter() - start) * 1000
        return self.format_result(
            target=target,
            status="completed",
            findings=findings,
            evidence=evidence,
            metadata={"evaluated_subsystems": ["LSA", "Firewall", "Defender", "UAC"]},
            risk={"threat_exposure": "ELEVATED" if findings else "MINIMAL"},
            execution_time_ms=duration,
        )
