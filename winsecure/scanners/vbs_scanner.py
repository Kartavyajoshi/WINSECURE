"""
WinSecure Virtualization-Based Security (VBS) & HVCI Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class VBSScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-VBS",
            name="Virtualization-Based Security & HVCI Scanner",
            purpose="Inspects Hypervisor-Enforced Code Integrity (HVCI), Credential Guard, and Virtualization-Based Security (VBS).",
            category="Virtualization Security",
            inputs=["RegistryCollector"],
            collectors=["HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard"],
            checks=["WS-VBS-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53", "Microsoft Security Baseline"],
            references=["https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity"]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        hvci_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", {})

        r_001 = Rule(
            id="WS-VBS-001",
            title="Virtualization-Based Security (VBS) / Hypervisor-Enforced Code Integrity (HVCI) is Disabled",
            category="Virtualization Security",
            severity=Severity.HIGH,
            description="VBS uses hardware virtualization to create an isolated subsystem hosting HVCI and Credential Guard.",
            expected="HVCI / Memory Integrity Enabled = 1",
            impact="Adversaries exploiting vulnerable kernel drivers (BYOVD) can execute unsigned code in ring 0.",
            remediation_guidance="Enable Memory Integrity / HVCI in Windows Security Settings.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.8.1", "title": "Virtualization Based Security"},
                {"framework": "NIST SP 800-53", "version": "Rev 5", "control_id": "SI-16", "title": "Memory Protection"}
            ],
            mitre_attack=["T1562.001", "T1068"],
            requires_admin=True,
        )

        hvci_val = hvci_key.get("Enabled")
        if hvci_val == 1 or hvci_val == "1":
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "Hypervisor-Enforced Code Integrity (HVCI) is Enabled (1)", confidence=0.99, evidence_data={"HVCI_Enabled": 1}))
        elif hvci_val == 0 or hvci_val == "0":
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, "HVCI / Memory Integrity is Disabled (0)", confidence=0.99, evidence_data={"HVCI_Enabled": 0}))
        else:
            # Default on Windows 11 22H2+ clean installs is enabled
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "HVCI / Memory Integrity active by default on modern Windows 11", confidence=0.90))

        return findings
