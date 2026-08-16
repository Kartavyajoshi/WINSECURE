"""
WinSecure Sysmon & Advanced Telemetry Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class SysmonScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-SYSMON",
            name="Sysmon & Advanced Telemetry Scanner",
            purpose="Inspects Microsoft Sysinternals Sysmon service state, kernel driver status, and deep telemetry collection readiness.",
            category="Advanced Logging",
            inputs=["ServicesCollector"],
            collectors=["Win32_Service (Sysmon)"],
            checks=["WS-SYS-003"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"]
        )

    def run(self) -> List[Finding]:
        findings = []
        svc_data = self.context.collected_artifacts.get("services", {})
        services = svc_data.get("services") or []

        r_003 = Rule(
            id="WS-SYS-003",
            title="Sysmon Advanced Endpoint Telemetry Service is Not Installed or Inactive",
            category="Advanced Logging",
            severity=Severity.INFORMATIONAL,
            description="Sysinternals Sysmon provides deep kernel-level event telemetry for process injection and file creation.",
            expected="Sysmon / Sysmon64 service is Running with active configuration",
            impact="Advanced living-off-the-land techniques cannot be investigated post-intrusion without kernel telemetry.",
            remediation_guidance="Deploy Sysmon with a vetted modular configuration: sysmon -i config.xml",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.14.2", "title": "Advanced Endpoint Telemetry"}
            ],
            mitre_attack=["T1059", "T1055"],
            requires_admin=True,
        )

        sysmon_svc = next((s for s in services if isinstance(s, dict) and s.get("Name", "").lower() in ["sysmon", "sysmon64"]), None)
        if sysmon_svc and sysmon_svc.get("State", "").lower() == "running":
            findings.append(self.create_finding(r_003, FindingStatus.PASS, "Sysmon service is installed and actively Running", confidence=0.99, evidence_data=sysmon_svc))
        elif sysmon_svc:
            findings.append(self.create_finding(r_003, FindingStatus.WARN, f"Sysmon service is installed but currently {sysmon_svc.get('State')}", confidence=0.95, evidence_data=sysmon_svc))
        else:
            findings.append(self.create_finding(r_003, FindingStatus.PASS, "Sysmon service is not installed on this host (Optional recommended EDR telemetry)", confidence=0.90))

        return findings
