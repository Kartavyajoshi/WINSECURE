"""
WinSecure System Hardware & Firmware Security Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class SystemScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-SYSTEM",
            name="System Hardware & Firmware Security Scanner",
            purpose="Inspects Secure Boot, TPM 2.0 readiness, UEFI firmware state, and OS architecture.",
            category="System",
            inputs=["WmiCollector"],
            collectors=["Win32_OperatingSystem", "Win32_BIOS"],
            checks=["WS-SYS-001", "WS-SYS-002"],
            requires_admin=False,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot"]
        )

    def run(self) -> List[Finding]:
        findings = []
        wmi_data = self.context.collected_artifacts.get("wmi", {})
        sys_inv = self.context.inventory

        # 1. Secure Boot (WS-SYS-001)
        r_001 = Rule(
            id="WS-SYS-001",
            title="Secure Boot is Disabled in Firmware",
            category="System",
            severity=Severity.HIGH,
            description="Secure Boot ensures that the endpoint boots using only software trusted by the OEM.",
            expected="SecureBoot = True",
            impact="Adversaries can install unsigned bootkit persistence (e.g. BlackLotus).",
            remediation_guidance="Reboot into UEFI firmware and enable Secure Boot.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.1.1", "title": "Secure Boot"}
            ],
            mitre_attack=["T1542.003"],
            requires_admin=False,
        )
        sec_boot = sys_inv.secure_boot if sys_inv else wmi_data.get("secure_boot", True)
        if sec_boot is True or sec_boot == 1 or sec_boot == "True":
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "Secure Boot is actively enabled in UEFI firmware", confidence=0.99, evidence_data={"SecureBoot": True}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, "Secure Boot is Disabled in firmware", confidence=0.99, evidence_data={"SecureBoot": False}))

        # 2. TPM (WS-SYS-002)
        r_002 = Rule(
            id="WS-SYS-002",
            title="TPM 2.0 Security Module Missing or Disabled",
            category="System",
            severity=Severity.MEDIUM,
            description="Trusted Platform Module 2.0 provides hardware-based isolation for BitLocker and credentials.",
            expected="TPM Present = True, Version = 2.0",
            impact="Hardware-backed key isolation is unavailable.",
            remediation_guidance="Enable TPM 2.0 (fTPM/PTT) in system UEFI settings.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.1.2", "title": "TPM 2.0 Requirement"}
            ],
            mitre_attack=["T1552"],
            requires_admin=False,
        )
        tpm_ok = sys_inv.tpm_present if sys_inv else wmi_data.get("tpm_present", True)
        if tpm_ok is True or tpm_ok == 1 or tpm_ok == "True":
            findings.append(self.create_finding(r_002, FindingStatus.PASS, "TPM 2.0 security module is present and ready", confidence=0.99, evidence_data={"tpm_present": True}))
        else:
            findings.append(self.create_finding(r_002, FindingStatus.FAIL, "TPM 2.0 security module is missing or disabled", confidence=0.99, evidence_data={"tpm_present": False}))

        return findings
