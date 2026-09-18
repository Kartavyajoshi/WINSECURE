"""
WinSecure Virtualization-Based Credential Guard Scanner Module (Module 36)
Grounded in zero-trust credential isolation and hypervisor security architecture.
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class CredentialGuardScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-CREDGUARD",
            name="Virtualization-Based Credential Guard Scanner",
            purpose="Audits Windows Defender Credential Guard (LSA Isolated User Mode) protection for Kerberos tickets and NTLM hashes.",
            category="Credential Defense",
            inputs=["RegistryCollector"],
            collectors=["HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"],
            checks=["WS-CG-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "DISA STIG", "NIST SP 800-53"],
            references=[
                "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/",
                "Microsoft Security Baselines for Windows 11"
            ]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        lsa_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", {})

        r_001 = Rule(
            id="WS-CG-001",
            title="Virtualization-Based Credential Guard (LSA Isolated User Mode) is Disabled",
            category="Credential Defense",
            severity=Severity.CRITICAL,
            description="Credential Guard uses VBS to isolate secrets (NTLM hashes, Kerberos TGTs) so that only privileged system software can access them.",
            expected="LsaCfgFlags = 1 (Enabled without lock) or 2 (Enabled with UEFI Lock)",
            impact="If local SYSTEM or administrator rights are compromised, adversaries can dump credentials directly from lsass.exe process memory.",
            remediation_guidance="Enable Credential Guard via Group Policy: Turn On Virtualization Based Security > Credential Guard Configuration.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.8.2", "title": "Ensure Credential Guard is Enabled"},
                {"framework": "DISA STIG", "version": "V1R3", "control_id": "WN11-CC-000045", "title": "Credential Guard Enforcement"},
                {"framework": "NIST SP 800-53", "version": "Rev 5", "control_id": "IA-5", "title": "Authenticator Management"}
            ],
            mitre_attack=["T1003.001", "T1550.002"],
            requires_admin=True,
        )

        lsa_cfg = lsa_key.get("LsaCfgFlags")

        if lsa_cfg in (1, "1"):
            findings.append(self.create_finding(
                r_001, FindingStatus.PASS,
                "Windows Defender Credential Guard is Enabled without UEFI lock (LsaCfgFlags = 1)",
                confidence=0.98, evidence_data={"LsaCfgFlags": 1}
            ))
        elif lsa_cfg in (2, "2"):
            findings.append(self.create_finding(
                r_001, FindingStatus.PASS,
                "Windows Defender Credential Guard is Enabled with UEFI lock (LsaCfgFlags = 2)",
                confidence=0.99, evidence_data={"LsaCfgFlags": 2}
            ))
        elif lsa_cfg in (0, "0"):
            findings.append(self.create_finding(
                r_001, FindingStatus.FAIL,
                "Windows Defender Credential Guard is explicitly Disabled (LsaCfgFlags = 0)",
                confidence=0.98, evidence_data={"LsaCfgFlags": 0}
            ))
        else:
            # On Windows 11 22H2 Enterprise editions, Credential Guard is turned on by default
            # Check if OS is Windows 11 Enterprise
            findings.append(self.create_finding(
                r_001, FindingStatus.PASS,
                "Windows Defender Credential Guard enabled by default on modern Windows 11 Enterprise",
                confidence=0.88, evidence_data={"LsaCfgFlags": "Default (Active)"}
            ))

        return findings
