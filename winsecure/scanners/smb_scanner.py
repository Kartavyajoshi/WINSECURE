"""
WinSecure SMB Protocol & Security Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class SMBScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-SMB",
            name="SMB Protocol & Server Security Scanner",
            purpose="Inspects SMBv1 legacy protocol status, packet signing enforcement, and guest authentication exposure.",
            category="SMB",
            inputs=["RegistryCollector"],
            collectors=["HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"],
            checks=["WS-SMB-001", "WS-SMB-002", "WS-SMB-003"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53", "Microsoft Security Baseline"],
            references=["https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        srv_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", {})
        ws_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", {})

        # 1. SMBv1 (WS-SMB-001)
        r_001 = Rule(
            id="WS-SMB-001",
            title="SMBv1 Legacy Protocol is Enabled",
            category="SMB",
            severity=Severity.CRITICAL,
            description="SMBv1 contains critical vulnerabilities exploited by EternalBlue, WannaCry, and NotPetya.",
            expected="SMB1 = 0 or Disabled",
            impact="Remote unauthenticated code execution and lateral movement via legacy protocol flaws.",
            remediation_guidance="Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.4.1", "title": "Disable SMBv1"}
            ],
            mitre_attack=["T1210"],
            requires_admin=True,
        )
        smb1_val = srv_key.get("SMB1")
        if smb1_val == 0 or smb1_val is None:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "SMBv1 is Disabled (SMB1 = 0 or absent)", confidence=0.99, evidence_data={"SMB1": smb1_val or 0}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"SMBv1 is ENABLED (SMB1 = {smb1_val}) - Critical Risk", confidence=0.99, evidence_data={"SMB1": smb1_val}))

        # 2. SMB Signing (WS-SMB-002)
        r_002 = Rule(
            id="WS-SMB-002",
            title="SMB Server Packet Signing is Not Required",
            category="SMB",
            severity=Severity.HIGH,
            description="SMB signing prevents man-in-the-middle (MitM) and SMB relay attacks.",
            expected="RequireSecuritySignature = 1",
            impact="Adversaries performing ARP spoofing or LLMNR poisoning can intercept/relay SMB sessions.",
            remediation_guidance="Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "2.3.8.1", "title": "SMB Digitally Sign Always"}
            ],
            mitre_attack=["T1557.001"],
            requires_admin=True,
        )
        sign_val = srv_key.get("RequireSecuritySignature")
        if sign_val == 1:
            findings.append(self.create_finding(r_002, FindingStatus.PASS, "RequireSecuritySignature = 1 (Signing Required)", confidence=0.99, evidence_data={"RequireSecuritySignature": 1}))
        else:
            findings.append(self.create_finding(r_002, FindingStatus.FAIL, f"RequireSecuritySignature = {sign_val or 0} (SMB Relay Vulnerable)", confidence=0.99, evidence_data={"RequireSecuritySignature": sign_val or 0}))

        # 3. Insecure Guest Auth (WS-SMB-003)
        r_003 = Rule(
            id="WS-SMB-003",
            title="Insecure Guest Authentication Allowed on SMB Client",
            category="SMB",
            severity=Severity.MEDIUM,
            description="Insecure guest logons allow unauthenticated access to rogue SMB file servers.",
            expected="AllowInsecureGuestAuth = 0",
            impact="Malicious network actors can host deceptive SMB shares to deliver malware.",
            remediation_guidance="Set AllowInsecureGuestAuth to 0 in HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.4.2", "title": "Insecure Guest Logons"}
            ],
            mitre_attack=["T1187"],
            requires_admin=True,
        )
        guest_auth = ws_key.get("AllowInsecureGuestAuth")
        if guest_auth == 0 or guest_auth is None:
            findings.append(self.create_finding(r_003, FindingStatus.PASS, "AllowInsecureGuestAuth = 0 (Disabled)", confidence=0.95, evidence_data={"AllowInsecureGuestAuth": 0}))
        else:
            findings.append(self.create_finding(r_003, FindingStatus.FAIL, f"AllowInsecureGuestAuth = {guest_auth} (Enabled)", confidence=0.95, evidence_data={"AllowInsecureGuestAuth": guest_auth}))

        return findings
