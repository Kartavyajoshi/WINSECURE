"""
WinSecure Remote Access & RDP Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class RemoteScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-REMOTE",
            name="Remote Access & RDP Security Scanner",
            purpose="Inspects Remote Desktop state, Network Level Authentication (NLA) enforcement, and encryption levels.",
            category="Remote Access",
            inputs=["RegistryCollector"],
            collectors=["HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"],
            checks=["WS-RDP-001", "WS-RDP-002"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53", "DISA STIG"],
            references=["https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-plan-manage-security"]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        ts_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", {})
        rdp_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", {})

        # Check if RDP is enabled (fDenyTSConnections == 0 means enabled)
        rdp_enabled = ts_key.get("fDenyTSConnections") == 0

        # 1. NLA Check (WS-RDP-001)
        r_001 = Rule(
            id="WS-RDP-001",
            title="Remote Desktop is Enabled Without Network Level Authentication (NLA)",
            category="Remote Access",
            severity=Severity.HIGH,
            description="NLA requires connecting clients to authenticate before creating an RDP session.",
            expected="UserAuthentication = 1 (NLA Required)",
            impact="Unauthenticated attackers can exploit pre-authentication RDP vulnerabilities.",
            remediation_guidance="Set UserAuthentication to 1 in RDP-Tcp key.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.65.1", "title": "RDP Network Level Authentication"}
            ],
            mitre_attack=["T1021.001"],
            requires_admin=True,
        )
        nla_val = rdp_key.get("UserAuthentication")
        if not rdp_enabled:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "Remote Desktop is completely disabled (fDenyTSConnections = 1)", confidence=0.99, evidence_data={"fDenyTSConnections": 1}))
        elif nla_val == 1:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "RDP is enabled and Network Level Authentication (NLA) is Enforced", confidence=0.99, evidence_data={"UserAuthentication": 1}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, "RDP is enabled but NLA is NOT enforced (UserAuthentication != 1)", confidence=0.99, evidence_data=rdp_key))

        # 2. RDP Encryption Level (WS-RDP-002)
        r_002 = Rule(
            id="WS-RDP-002",
            title="RDP Encryption Level is Weak",
            category="Remote Access",
            severity=Severity.MEDIUM,
            description="RDP sessions should enforce High encryption (128-bit) or FIPS-compliant encryption.",
            expected="MinEncryptionLevel >= 3 (High)",
            impact="Remote desktop session traffic may be eavesdropped on or decrypted.",
            remediation_guidance="Set MinEncryptionLevel to 3 in RDP-Tcp registry key.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.65.2", "title": "RDP Encryption Level"}
            ],
            mitre_attack=["T1021.001"],
            requires_admin=True,
        )
        enc_lvl = rdp_key.get("MinEncryptionLevel")
        if not rdp_enabled:
            findings.append(self.create_finding(r_002, FindingStatus.NOT_APPLICABLE, "RDP is disabled on this endpoint", confidence=0.99))
        elif isinstance(enc_lvl, int) and enc_lvl >= 3:
            findings.append(self.create_finding(r_002, FindingStatus.PASS, f"MinEncryptionLevel = {enc_lvl} (High/FIPS)", confidence=0.95, evidence_data={"MinEncryptionLevel": enc_lvl}))
        else:
            findings.append(self.create_finding(r_002, FindingStatus.WARN, f"MinEncryptionLevel = {enc_lvl or 0} (Default/Client Compatible)", confidence=0.90, evidence_data={"MinEncryptionLevel": enc_lvl}))

        return findings
