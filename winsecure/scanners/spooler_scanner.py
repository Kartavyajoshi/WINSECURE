"""
WinSecure Print Spooler Security Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class SpoolerScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-SPOOLER",
            name="Print Spooler Hardening Scanner",
            purpose="Inspects Print Spooler service state to prevent remote code execution and privilege escalation (PrintNightmare).",
            category="Services",
            inputs=["ServicesCollector"],
            collectors=["Win32_Service (Spooler)"],
            checks=["WS-SPL-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/point-and-print-restrictions"]
        )

    def run(self) -> List[Finding]:
        findings = []
        svc_data = self.context.collected_artifacts.get("services", {})
        services = svc_data.get("services") or []

        r_001 = Rule(
            id="WS-SPL-001",
            title="Print Spooler Service is Running on Non-Print Server Endpoint (PrintNightmare Exposure)",
            category="Services",
            severity=Severity.MEDIUM,
            description="The Print Spooler service should be disabled on workstations without physical printers.",
            expected="Spooler Service Disabled or Inbound Remote Printing Blocked",
            impact="Adversaries on local subnets can exploit Print Spooler RPC interfaces for privilege escalation.",
            remediation_guidance="Stop-Service -Name 'Spooler'; Set-Service -Name 'Spooler' -StartupType Disabled",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.21.1", "title": "Print Spooler Security"}
            ],
            mitre_attack=["T1068"],
            requires_admin=True,
        )

        spooler = next((s for s in services if isinstance(s, dict) and s.get("Name", "").lower() == "spooler"), None)
        if not spooler:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "Print Spooler service is stopped or disabled", confidence=0.95))
        else:
            state = spooler.get("State", "")
            if state.lower() == "running":
                findings.append(self.create_finding(r_001, FindingStatus.WARN, "Print Spooler service is Running (Consider disabling if not using printers)", confidence=0.90, evidence_data=spooler))
            else:
                findings.append(self.create_finding(r_001, FindingStatus.PASS, f"Print Spooler service state is {state} (Not active)", confidence=0.99, evidence_data=spooler))

        return findings
