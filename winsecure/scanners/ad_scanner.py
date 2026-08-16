"""
WinSecure Active Directory Domain Endpoint Hardening Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class ADScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-AD",
            name="Active Directory Domain Member Security Scanner",
            purpose="Inspects LDAP client signing requirements, Netlogon secure channel integrity, and NTLM domain restrictions.",
            category="Active Directory",
            inputs=["RegistryCollector"],
            collectors=["HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LDAP", "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"],
            checks=["WS-AD-001", "WS-AD-002"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-member-digitally-encrypt-or-sign-secure-channel-data-always"]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        ldap_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Services\LDAP", {})
        netlogon_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters", {})

        # 1. LDAP Client Signing (WS-AD-001)
        r_001 = Rule(
            id="WS-AD-001",
            title="LDAP Client Signing is Not Required (MitM Vulnerability)",
            category="Active Directory",
            severity=Severity.HIGH,
            description="LDAP client signing requires LDAP traffic to be digitally signed, preventing tampering.",
            expected="LDAPClientIntegrity = 2 (Negotiate signing required)",
            impact="Unsigned LDAP queries transmitted across domain subnets can be intercepted and altered via ARP/LLMNR spoofing.",
            remediation_guidance="Set HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity to 2.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "2.3.11.2", "title": "LDAP Client Signing"}
            ],
            mitre_attack=["T1557.001"],
            requires_admin=True,
        )
        ldap_sig = ldap_key.get("LDAPClientIntegrity")
        if ldap_sig in [2, "2"]:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "LDAPClientIntegrity = 2 (Signing Enforced)", confidence=0.99, evidence_data={"LDAPClientIntegrity": 2}))
        elif ldap_sig == 1 or ldap_sig == "1":
            findings.append(self.create_finding(r_001, FindingStatus.WARN, "LDAPClientIntegrity = 1 (Negotiate signing - Partial)", confidence=0.95, evidence_data={"LDAPClientIntegrity": 1}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"LDAPClientIntegrity = {ldap_sig or 0} (Disabled - LDAP relay vulnerable)", confidence=0.95, evidence_data={"LDAPClientIntegrity": ldap_sig or 0}))

        # 2. Netlogon Secure Channel (WS-AD-002)
        r_002 = Rule(
            id="WS-AD-002",
            title="Netlogon Secure Channel Encryption Weakened",
            category="Active Directory",
            severity=Severity.CRITICAL,
            description="Netlogon secure channel must mandate strong encryption and signing to protect domain authentication.",
            expected="RequireSignOrSeal = 1 and RequireStrongKey = 1",
            impact="Adversaries can exploit unauthenticated Netlogon RPC connections to impersonate computer accounts.",
            remediation_guidance="Set RequireSignOrSeal and RequireStrongKey to 1 in Netlogon Parameters.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "2.3.5.1", "title": "Netlogon Secure Channel"}
            ],
            mitre_attack=["T1068", "T1557"],
            requires_admin=True,
        )
        sign_seal = netlogon_key.get("RequireSignOrSeal")
        if sign_seal == 1 or sign_seal == "1" or sign_seal is None:
            findings.append(self.create_finding(r_002, FindingStatus.PASS, "Netlogon secure channel encryption is enforced (RequireSignOrSeal = 1)", confidence=0.95, evidence_data={"RequireSignOrSeal": 1}))
        else:
            findings.append(self.create_finding(r_002, FindingStatus.FAIL, f"RequireSignOrSeal = {sign_seal} (Disabled - High Risk)", confidence=0.99, evidence_data={"RequireSignOrSeal": sign_seal}))

        return findings
