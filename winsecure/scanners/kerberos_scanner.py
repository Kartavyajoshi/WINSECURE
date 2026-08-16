"""
WinSecure Kerberos & Authentication Hardening Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class KerberosScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-KERBEROS",
            name="Kerberos Authentication & Encryption Scanner",
            purpose="Inspects Kerberos encryption types to prevent weak DES/RC4 usage in tickets.",
            category="Authentication",
            inputs=["RegistryCollector"],
            collectors=["HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters"],
            checks=["WS-KERB-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        kerb_key = reg.get(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters", {})

        r_001 = Rule(
            id="WS-KERB-001",
            title="Kerberos DES and RC4 Weak Encryption Types are Permitted",
            category="Authentication",
            severity=Severity.MEDIUM,
            description="DES and RC4 encryption types in Kerberos should be disallowed in favor of AES-128 and AES-256.",
            expected="SupportedEncryptionTypes does not allow DES or RC4",
            impact="Kerberoasting and ticket-forgery attacks can crack hashes faster using RC4.",
            remediation_guidance="Set SupportedEncryptionTypes to 0x7ffffff8 (AES only).",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "2.3.11.5", "title": "Kerberos Encryption Types"}
            ],
            mitre_attack=["T1558.003"],
            requires_admin=True,
        )

        enc_types = kerb_key.get("SupportedEncryptionTypes")
        if enc_types is None:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "Kerberos encryption types set to default (AES preferred on modern builds)", confidence=0.90))
        elif isinstance(enc_types, int) and (enc_types & 0x7) == 0:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, f"SupportedEncryptionTypes = 0x{enc_types:x} (DES/RC4 disabled)", confidence=0.99, evidence_data={"SupportedEncryptionTypes": hex(enc_types)}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.WARN, f"SupportedEncryptionTypes = {enc_types} (Permits legacy RC4/DES)", confidence=0.90, evidence_data={"SupportedEncryptionTypes": enc_types}))

        return findings
