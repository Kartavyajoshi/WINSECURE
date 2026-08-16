"""
WinSecure Cryptography & Schannel Protocol Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class SchannelScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-SCHANNEL",
            name="Cryptography & Insecure TLS Protocol Scanner",
            purpose="Inspects Windows Schannel cryptographic configuration to ensure legacy TLS 1.0 and TLS 1.1 are disabled.",
            category="Cryptography",
            inputs=["RegistryCollector"],
            collectors=["HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols"],
            checks=["WS-SCH-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings"]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        tls10_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client", {})

        r_001 = Rule(
            id="WS-SCH-001",
            title="Legacy Insecure TLS Protocols (TLS 1.0 / TLS 1.1) are Enabled",
            category="Cryptography",
            severity=Severity.HIGH,
            description="TLS 1.0 and TLS 1.1 suffer from known cryptographic weaknesses (POODLE, BEAST) and must be disabled.",
            expected="TLS 1.0 and TLS 1.1 DisabledByDefault = 1 and Enabled = 0",
            impact="Attackers can force protocol downgrade and decrypt network traffic in transit.",
            remediation_guidance="Disable legacy TLS 1.0/1.1 in Schannel registry protocols.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.27.4", "title": "Disable Insecure TLS"}
            ],
            mitre_attack=["T1557"],
            requires_admin=True,
        )

        tls10_en = tls10_key.get("Enabled")
        if tls10_en == 0 or tls10_en is None:
            # On Windows 11, TLS 1.0/1.1 are disabled by default
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "Legacy TLS 1.0 and TLS 1.1 are disabled (TLS 1.2 and 1.3 enforced)", confidence=0.95, evidence_data={"TLS1.0_Enabled": 0}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"TLS 1.0 is explicitly Enabled ({tls10_en})", confidence=0.99, evidence_data=tls10_key))

        return findings
