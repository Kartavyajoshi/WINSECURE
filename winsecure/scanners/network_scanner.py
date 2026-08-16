"""
WinSecure Network Configuration Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class NetworkScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-NETWORK",
            name="Network Configuration & Exposure Scanner",
            purpose="Inspects LLMNR protocol state, NetBIOS, listening TCP ports, and network exposures.",
            category="Network",
            inputs=["RegistryCollector", "NetworkCollector"],
            collectors=["HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "Get-NetTCPConnection"],
            checks=["WS-NET-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/bb726985(v=technet.10)"]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        dns_key = reg.get(r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", {})

        # 1. LLMNR (WS-NET-001)
        r_001 = Rule(
            id="WS-NET-001",
            title="LLMNR Name Resolution is Enabled (Poisoning Exposure)",
            category="Network",
            severity=Severity.HIGH,
            description="LLMNR allows fallback name resolution via broadcast, enabling Responder/MitM credential capture.",
            expected="EnableMulticast = 0",
            impact="Adversaries on the local subnet can spoof responses and capture NetNTLMv2 hashes.",
            remediation_guidance="Set EnableMulticast to 0 in HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.15.1", "title": "Turn off multicast name resolution"}
            ],
            mitre_attack=["T1557.001"],
            requires_admin=True,
        )
        llmnr_val = dns_key.get("EnableMulticast")
        if llmnr_val == 0:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "EnableMulticast = 0 (LLMNR Disabled)", confidence=0.99, evidence_data={"EnableMulticast": 0}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"EnableMulticast = {llmnr_val if llmnr_val is not None else '1 (Default Enabled)'}", confidence=0.95, evidence_data={"EnableMulticast": llmnr_val}))

        return findings
