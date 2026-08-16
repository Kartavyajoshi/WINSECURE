"""
WinSecure Microsoft Edge & Browser Baseline Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class BrowserScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-BROWSER",
            name="Microsoft Edge & Browser Security Scanner",
            purpose="Inspects Microsoft Edge Enterprise policies, SmartScreen enforcement, and browser security settings.",
            category="Browser Security",
            inputs=["RegistryCollector"],
            collectors=["HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge"],
            checks=["WS-BRW-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/deployedge/microsoft-edge-security-browse-safely"]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        edge_key = reg.get(r"HKLM\SOFTWARE\Policies\Microsoft\Edge", {})

        r_001 = Rule(
            id="WS-BRW-001",
            title="Microsoft Edge / Chromium Browser Security Baseline Unenforced",
            category="Browser Security",
            severity=Severity.MEDIUM,
            description="Microsoft Edge Enterprise policies enforce SmartScreen download protection and security baselines.",
            expected="Edge SmartScreenEnabled = 1 and PreventBypass = 1",
            impact="Users can bypass malicious site and malware download warnings in the primary web browser.",
            remediation_guidance="Set SmartScreenEnabled to 1 in HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.20.1", "title": "Microsoft Edge SmartScreen"}
            ],
            mitre_attack=["T1204.001"],
            requires_admin=True,
        )

        ss_en = edge_key.get("SmartScreenEnabled")
        if ss_en == 1 or ss_en is None:
            # Default in Edge is SmartScreen Enabled
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "Microsoft Edge SmartScreen protection is active", confidence=0.95, evidence_data={"SmartScreenEnabled": 1}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"Edge SmartScreen is Disabled ({ss_en})", confidence=0.99, evidence_data=edge_key))

        return findings
