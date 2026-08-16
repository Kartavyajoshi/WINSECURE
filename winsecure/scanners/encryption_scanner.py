"""
WinSecure BitLocker & Device Encryption Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class EncryptionScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-ENCRYPTION",
            name="BitLocker & Drive Encryption Scanner",
            purpose="Inspects BitLocker protection status, volume encryption state, and cipher algorithms (WITHOUT exposing keys).",
            category="Encryption",
            inputs=["BitLockerCollector"],
            collectors=["Get-BitLockerVolume"],
            checks=["WS-ENC-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53", "DISA STIG"],
            references=["https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/"]
        )

    def run(self) -> List[Finding]:
        findings = []
        bl_data = self.context.collected_artifacts.get("bitlocker", {})
        volumes = bl_data.get("volumes") or []
        if isinstance(volumes, dict):
            volumes = [volumes]

        os_vol = next((v for v in volumes if v.get("MountPoint") == "C:" or v.get("VolumeType") == "OperatingSystem"), None)

        r_001 = Rule(
            id="WS-ENC-001",
            title="BitLocker Device Encryption is Disabled on OS Volume",
            category="Encryption",
            severity=Severity.HIGH,
            description="BitLocker full-volume encryption protects data at rest against offline physical attacks.",
            expected="ProtectionStatus = 1 (On)",
            impact="Physical extraction of disk grants full unencrypted access to local files and SAM database.",
            remediation_guidance="Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.2.1", "title": "BitLocker OS Drive"},
                {"framework": "NIST SP 800-53", "version": "Rev 5", "control_id": "SC-28", "title": "Data at Rest"}
            ],
            mitre_attack=["T1005"],
            requires_admin=True,
        )

        if not os_vol:
            # Check if fixture provides status
            if "bitlocker_active" in bl_data:
                active = bl_data["bitlocker_active"]
                st = FindingStatus.PASS if active else FindingStatus.FAIL
                findings.append(self.create_finding(r_001, st, f"BitLocker Active = {active}", confidence=0.95))
            else:
                findings.append(self.create_finding(r_001, FindingStatus.UNKNOWN, "BitLocker volume information could not be determined", confidence=0.5))
        else:
            prot_status = os_vol.get("ProtectionStatus")
            if prot_status in [1, "On", "1"]:
                findings.append(self.create_finding(r_001, FindingStatus.PASS, "BitLocker is actively protecting OS volume (ProtectionStatus = On)", confidence=0.99, evidence_data=os_vol))
            else:
                findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"BitLocker ProtectionStatus = {prot_status} (Off)", confidence=0.99, evidence_data=os_vol))

        return findings
