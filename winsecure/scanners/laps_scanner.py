"""
WinSecure Windows LAPS Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class LAPSScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-LAPS",
            name="Windows LAPS (Local Administrator Password Solution) Scanner",
            purpose="Inspects Windows LAPS configuration, password rotation policy, and Active Directory / Azure AD backup target.",
            category="Authentication",
            inputs=["RegistryCollector"],
            collectors=["HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LAPS"],
            checks=["WS-LAPS-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        laps_key = reg.get(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LAPS", {})

        r_001 = Rule(
            id="WS-LAPS-001",
            title="Local Administrator Password Solution (Windows LAPS) is Not Configured",
            category="Authentication",
            severity=Severity.HIGH,
            description="Windows LAPS automatically manages and rotates the password of a local administrator account.",
            expected="LAPS BackupDirectory configured (Active Directory or Azure AD)",
            impact="Static, shared local administrator passwords enable catastrophic lateral movement.",
            remediation_guidance="Configure Windows LAPS via Group Policy or Intune.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "2.3.1.3", "title": "Windows LAPS Policy"}
            ],
            mitre_attack=["T1078.003", "T1550.002"],
            requires_admin=True,
        )

        bdir = laps_key.get("BackupDirectory")
        if bdir in [1, 2, "1", "2"]:
            target = "Active Directory" if str(bdir) == "1" else "Azure Active Directory"
            findings.append(self.create_finding(r_001, FindingStatus.PASS, f"Windows LAPS is configured to back up to {target}", confidence=0.99, evidence_data={"BackupDirectory": bdir}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.WARN, "Windows LAPS policy not explicitly configured in registry", confidence=0.90))

        return findings
