"""
WinSecure User Account Control (UAC) Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class UACScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-UAC",
            name="User Account Control (UAC) Security Scanner",
            purpose="Inspects UAC status, Administrator elevation behavior, Secure Desktop enforcement, and Admin Approval Mode.",
            category="UAC",
            inputs=["RegistryCollector"],
            collectors=["HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"],
            checks=["WS-UAC-001", "WS-UAC-002", "WS-UAC-003"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53", "Microsoft Security Baseline"],
            references=["https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/"]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        uac_key = reg.get(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", {})

        # 1. EnableLUA (WS-UAC-001)
        r_001 = Rule(
            id="WS-UAC-001",
            title="User Account Control (UAC) is Disabled",
            category="UAC",
            severity=Severity.CRITICAL,
            description="UAC prevents unauthorized malware from silently acquiring administrator privileges.",
            expected="EnableLUA = 1",
            impact="All applications run with full administrative rights without prompt or isolation.",
            remediation_guidance="Set HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA to 1.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "2.3.17.1", "title": "Admin Approval Mode"},
                {"framework": "NIST SP 800-53", "version": "Rev 5", "control_id": "AC-6", "title": "Least Privilege"}
            ],
            mitre_attack=["T1548.002"],
            requires_admin=True,
        )
        lua_val = uac_key.get("EnableLUA")
        if lua_val is None:
            findings.append(self.create_finding(r_001, FindingStatus.UNKNOWN, "EnableLUA registry key not found", confidence=0.5))
        elif lua_val == 1:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "UAC is active and EnableLUA = 1", confidence=0.99, evidence_data={"EnableLUA": 1}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"EnableLUA = {lua_val} (UAC Disabled)", confidence=0.99, evidence_data={"EnableLUA": lua_val}))

        # 2. PromptOnSecureDesktop (WS-UAC-002)
        r_002 = Rule(
            id="WS-UAC-002",
            title="UAC Secure Desktop Elevation is Disabled",
            category="UAC",
            severity=Severity.HIGH,
            description="Secure Desktop isolates credential prompts from standard desktop windows.",
            expected="PromptOnSecureDesktop = 1",
            impact="Malicious processes can spoof UAC prompts or inject simulated clicks.",
            remediation_guidance="Set PromptOnSecureDesktop to 1.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "2.3.17.6", "title": "Secure Desktop Elevation"}
            ],
            mitre_attack=["T1548.002"],
            requires_admin=True,
        )
        sd_val = uac_key.get("PromptOnSecureDesktop")
        if sd_val is None:
            findings.append(self.create_finding(r_002, FindingStatus.UNKNOWN, "PromptOnSecureDesktop key not found", confidence=0.5))
        elif sd_val == 1:
            findings.append(self.create_finding(r_002, FindingStatus.PASS, "PromptOnSecureDesktop = 1 (Secure Desktop Active)", confidence=0.99, evidence_data={"PromptOnSecureDesktop": 1}))
        else:
            findings.append(self.create_finding(r_002, FindingStatus.FAIL, f"PromptOnSecureDesktop = {sd_val} (Disabled)", confidence=0.99, evidence_data={"PromptOnSecureDesktop": sd_val}))

        # 3. ConsentPromptBehaviorAdmin (WS-UAC-003)
        r_003 = Rule(
            id="WS-UAC-003",
            title="UAC Administrator Elevation Behavior Set to Elevate Without Prompting",
            category="UAC",
            severity=Severity.CRITICAL,
            description="ConsentPromptBehaviorAdmin must prompt for consent (2 or 5) rather than silently elevating.",
            expected="ConsentPromptBehaviorAdmin in [2, 5]",
            impact="Software running in user context can escalate directly to SYSTEM/High-Integrity without review.",
            remediation_guidance="Set ConsentPromptBehaviorAdmin to 2 or 5.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "2.3.17.2", "title": "Consent Prompt Behavior"}
            ],
            mitre_attack=["T1548.002"],
            requires_admin=True,
        )
        cp_val = uac_key.get("ConsentPromptBehaviorAdmin")
        if cp_val is None:
            findings.append(self.create_finding(r_003, FindingStatus.UNKNOWN, "ConsentPromptBehaviorAdmin not found", confidence=0.5))
        elif cp_val in [2, 5]:
            findings.append(self.create_finding(r_003, FindingStatus.PASS, f"ConsentPromptBehaviorAdmin = {cp_val} (Prompt for Consent)", confidence=0.99, evidence_data={"ConsentPromptBehaviorAdmin": cp_val}))
        elif cp_val == 0:
            findings.append(self.create_finding(r_003, FindingStatus.FAIL, "ConsentPromptBehaviorAdmin = 0 (Elevate without prompting - Dangerous)", confidence=0.99, evidence_data={"ConsentPromptBehaviorAdmin": 0}))
        else:
            findings.append(self.create_finding(r_003, FindingStatus.WARN, f"ConsentPromptBehaviorAdmin = {cp_val}", confidence=0.90, evidence_data={"ConsentPromptBehaviorAdmin": cp_val}))

        return findings
