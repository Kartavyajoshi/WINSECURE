"""
WinSecure Windows Firewall Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class FirewallScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-FIREWALL",
            name="Windows Firewall Security Scanner",
            purpose="Assesses domain, private, and public firewall profiles, default inbound/outbound rules, and overly broad port exposures.",
            category="Firewall",
            inputs=["FirewallCollector"],
            collectors=["Get-NetFirewallProfile", "Get-NetFirewallRule"],
            checks=["WS-FW-001", "WS-FW-002", "WS-FW-003", "WS-FW-004"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53", "DISA STIG"],
            references=["https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/"]
        )

    def run(self) -> List[Finding]:
        findings = []
        fw_data = self.context.collected_artifacts.get("firewall", {})
        profiles = fw_data.get("Profiles") or []
        if isinstance(profiles, dict):
            profiles = [profiles]

        prof_map = {}
        for p in profiles:
            name = str(p.get("Name", "")).lower()
            prof_map[name] = p

        # 1. Public Profile State (WS-FW-001)
        r_001 = Rule(
            id="WS-FW-001",
            title="Public Firewall Profile is Disabled",
            category="Firewall",
            severity=Severity.CRITICAL,
            description="The Public profile protects endpoints on untrusted networks.",
            expected="Public Profile Enabled = True",
            impact="Host accepts unsolicited inbound connections on public networks.",
            remediation_guidance="Set-NetFirewallProfile -Profile Public -Enabled True",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "9.3.1", "title": "Public Profile State"},
                {"framework": "NIST SP 800-53", "version": "Rev 5", "control_id": "SC-7", "title": "Boundary Protection"},
            ],
            mitre_attack=["T1562.004"],
            requires_admin=True,
        )
        pub_p = prof_map.get("public")
        if not pub_p:
            findings.append(self.create_finding(r_001, FindingStatus.UNKNOWN, "Public profile not found or could not be queried", confidence=0.5))
        elif pub_p.get("Enabled") is True or pub_p.get("Enabled") == 1 or pub_p.get("Enabled") == "True":
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "Public firewall profile is active and Enabled", confidence=0.99, evidence_data=pub_p))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, "Public firewall profile is Disabled (False)", confidence=0.99, evidence_data=pub_p))

        # 2. Domain Profile State (WS-FW-002)
        r_002 = Rule(
            id="WS-FW-002",
            title="Domain Firewall Profile is Disabled",
            category="Firewall",
            severity=Severity.HIGH,
            description="The Domain profile enforces boundary controls when connected to corporate networks.",
            expected="Domain Profile Enabled = True",
            impact="Lateral movement across domain endpoints can proceed without firewall barriers.",
            remediation_guidance="Set-NetFirewallProfile -Profile Domain -Enabled True",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "9.1.1", "title": "Domain Profile State"}
            ],
            mitre_attack=["T1562.004"],
            requires_admin=True,
        )
        dom_p = prof_map.get("domain")
        if not dom_p:
            findings.append(self.create_finding(r_002, FindingStatus.UNKNOWN, "Domain profile not found", confidence=0.5))
        elif dom_p.get("Enabled") is True or dom_p.get("Enabled") == 1 or dom_p.get("Enabled") == "True":
            findings.append(self.create_finding(r_002, FindingStatus.PASS, "Domain firewall profile is active and Enabled", confidence=0.99, evidence_data=dom_p))
        else:
            findings.append(self.create_finding(r_002, FindingStatus.FAIL, "Domain firewall profile is Disabled (False)", confidence=0.99, evidence_data=dom_p))

        # 3. Private Profile State (WS-FW-003)
        r_003 = Rule(
            id="WS-FW-003",
            title="Private Firewall Profile is Disabled",
            category="Firewall",
            severity=Severity.HIGH,
            description="The Private profile enforces rules for home/work networks.",
            expected="Private Profile Enabled = True",
            impact="Compromised LAN devices can probe and exploit host services.",
            remediation_guidance="Set-NetFirewallProfile -Profile Private -Enabled True",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "9.2.1", "title": "Private Profile State"}
            ],
            mitre_attack=["T1562.004"],
            requires_admin=True,
        )
        priv_p = prof_map.get("private")
        if not priv_p:
            findings.append(self.create_finding(r_003, FindingStatus.UNKNOWN, "Private profile not found", confidence=0.5))
        elif priv_p.get("Enabled") is True or priv_p.get("Enabled") == 1 or priv_p.get("Enabled") == "True":
            findings.append(self.create_finding(r_003, FindingStatus.PASS, "Private firewall profile is active and Enabled", confidence=0.99, evidence_data=priv_p))
        else:
            findings.append(self.create_finding(r_003, FindingStatus.FAIL, "Private firewall profile is Disabled (False)", confidence=0.99, evidence_data=priv_p))

        # 4. Inbound Default Block (WS-FW-004)
        r_004 = Rule(
            id="WS-FW-004",
            title="Default Inbound Action is Allowed on Public Profile",
            category="Firewall",
            severity=Severity.CRITICAL,
            description="Inbound connections on the public profile must default to Block.",
            expected="DefaultInboundAction = Block",
            impact="All incoming ports without explicit blocking rules are open by default.",
            remediation_guidance="Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "9.3.2", "title": "Public Inbound Block"}
            ],
            mitre_attack=["T1562.004"],
            requires_admin=True,
        )
        if pub_p:
            inbound_act = str(pub_p.get("DefaultInboundAction", "")).lower()
            if "block" in inbound_act:
                findings.append(self.create_finding(r_004, FindingStatus.PASS, "Public default inbound action is Block (Default)", confidence=0.99, evidence_data=pub_p))
            elif "allow" in inbound_act:
                findings.append(self.create_finding(r_004, FindingStatus.FAIL, "Public default inbound action is Allow (Dangerous)", confidence=0.99, evidence_data=pub_p))
            else:
                findings.append(self.create_finding(r_004, FindingStatus.UNKNOWN, f"DefaultInboundAction = {inbound_act}", confidence=0.5))
        else:
            findings.append(self.create_finding(r_004, FindingStatus.UNKNOWN, "Public profile not available", confidence=0.5))

        return findings
