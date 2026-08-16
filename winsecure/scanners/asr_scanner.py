"""
WinSecure Defender Attack Surface Reduction (ASR) Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class ASRScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-ASR",
            name="Defender Attack Surface Reduction (ASR) Scanner",
            purpose="Inspects Defender ASR rules blocking macro child processes, credential stealing, and script obfuscation.",
            category="Defender",
            inputs=["DefenderCollector"],
            collectors=["Get-MpPreference"],
            checks=["WS-ASR-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53", "Microsoft Security Baseline"],
            references=["https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference"]
        )

    def run(self) -> List[Finding]:
        findings = []
        defender_data = self.context.collected_artifacts.get("defender", {})
        pref_info = defender_data.get("Preferences") or {}

        r_001 = Rule(
            id="WS-ASR-001",
            title="Defender Attack Surface Reduction (ASR) Rules are Unconfigured or in Audit Mode",
            category="Defender",
            severity=Severity.HIGH,
            description="Attack Surface Reduction rules block weaponized Office macros, obfuscated scripts, and LSASS stealing.",
            expected="Core ASR rules enabled in Block mode (Action = 1)",
            impact="Malicious Office documents and script download cradles can spawn processes unchecked.",
            remediation_guidance="Enable core ASR rules in block mode via Group Policy or Add-MpPreference.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.46.7", "title": "Configure ASR Rules"}
            ],
            mitre_attack=["T1566.001", "T1059.005"],
            requires_admin=True,
        )

        actions = pref_info.get("AttackSurfaceReductionRules_Actions") or []
        if isinstance(actions, int):
            actions = [actions]
        
        block_rules = [a for a in actions if a == 1 or a == "1"]
        if block_rules:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, f"ASR rules configured with {len(block_rules)} rules in Block mode", confidence=0.99, evidence_data={"block_rules_count": len(block_rules)}))
        elif actions:
            findings.append(self.create_finding(r_001, FindingStatus.WARN, f"ASR rules active in Audit mode ({len(actions)} rules)", confidence=0.95, evidence_data={"actions": actions}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, "No Defender Attack Surface Reduction (ASR) rules are active", confidence=0.95))

        return findings
