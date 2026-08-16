"""
WinSecure SmartScreen Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class SmartScreenScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-SMARTSCREEN",
            name="Windows Defender SmartScreen Scanner",
            purpose="Inspects SmartScreen for Windows Explorer and Edge browser download verification.",
            category="SmartScreen",
            inputs=["RegistryCollector"],
            collectors=["HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"],
            checks=["WS-SS-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/windows-defender-smartscreen/"]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        sys_key = reg.get(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System", {})

        r_001 = Rule(
            id="WS-SS-001",
            title="Windows Defender SmartScreen for Explorer is Disabled",
            category="SmartScreen",
            severity=Severity.HIGH,
            description="SmartScreen warns users before running unrecognized downloaded applications.",
            expected="EnableSmartScreen = 1",
            impact="Users can execute downloaded malicious executables without reputation warnings.",
            remediation_guidance="Set EnableSmartScreen to 1 in HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.28.1", "title": "Configure SmartScreen"}
            ],
            mitre_attack=["T1204.002"],
            requires_admin=True,
        )
        ss_val = sys_key.get("EnableSmartScreen")
        if ss_val == 1 or ss_val is None:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, f"EnableSmartScreen = {ss_val if ss_val is not None else '1 (Default)'}", confidence=0.95, evidence_data={"EnableSmartScreen": 1}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"EnableSmartScreen = {ss_val} (Disabled)", confidence=0.99, evidence_data={"EnableSmartScreen": ss_val}))

        return findings
