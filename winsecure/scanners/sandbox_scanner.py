"""
WinSecure Windows Sandbox & System Isolation Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class SandboxScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-SANDBOX",
            name="Windows Sandbox & Isolation Platform Scanner",
            purpose="Inspects Hypervisor platform readiness for Windows Sandbox containerized execution.",
            category="System Isolation",
            inputs=["WmiCollector"],
            collectors=["Win32_Processor", "Win32_ComputerSystem"],
            checks=["WS-SND-001"],
            requires_admin=False,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-sandbox"]
        )

    def run(self) -> List[Finding]:
        findings = []
        wmi = self.context.collected_artifacts.get("wmi", {})

        r_001 = Rule(
            id="WS-SND-001",
            title="Windows Hypervisor and Virtualization Platform Readiness",
            category="System Isolation",
            severity=Severity.LOW,
            description="Windows Hypervisor platform provides the substrate for Windows Sandbox application isolation.",
            expected="HypervisorPresent = True",
            impact="Containerized application isolation cannot be provisioned without virtualization.",
            remediation_guidance="Enable Hyper-V and Windows Hypervisor Platform.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.8.2", "title": "Virtualization Platform Readiness"}
            ],
            mitre_attack=["T1562"],
            requires_admin=False,
        )

        hyp = wmi.get("hypervisor_present", True)
        if hyp:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "Hypervisor platform is active and ready for containerized isolation", confidence=0.95))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.WARN, "Hypervisor platform is not detected on this endpoint", confidence=0.85))

        return findings
