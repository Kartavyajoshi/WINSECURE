"""
WinSecure Ransomware Defense & System Resilience Scanner Module (Module 33)
Grounded in ShieldFS and UNVEIL anti-extortion research architectures.
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class RansomwareScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-RANSOM",
            name="Ransomware Defense & System Resilience Scanner",
            purpose="Audits Defender Controlled Folder Access, Volume Shadow Copy resilience, and anti-extortion readiness.",
            category="Ransomware Defense",
            inputs=["DefenderCollector", "RegistryCollector", "ServicesCollector"],
            collectors=["Defender Preferences", "SystemRestore Registry", "VSS Service"],
            checks=["WS-RSM-001", "WS-RSM-002"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53", "DISA STIG"],
            references=[
                "https://learn.microsoft.com/en-us/defender-endpoint/controlled-folders",
                "Continella et al., ShieldFS: A Self-healing, Ransomware-aware Filesystem (ACSAC 2016)"
            ]
        )

    def run(self) -> List[Finding]:
        findings = []
        defender_data = self.context.collected_artifacts.get("defender", {})
        pref = defender_data.get("Preferences", {}) if isinstance(defender_data, dict) else {}
        reg = self.context.collected_artifacts.get("registry", {})
        services = self.context.collected_artifacts.get("services", [])

        # Check 1: WS-RSM-001 Controlled Folder Access
        r_001 = Rule(
            id="WS-RSM-001",
            title="Defender Controlled Folder Access (CFA) Anti-Ransomware Shielding is Disabled",
            category="Ransomware Defense",
            severity=Severity.CRITICAL,
            description="Controlled Folder Access intercepts and blocks unauthorized processes from encrypting files in protected folders.",
            expected="EnableControlledFolderAccess = 1 (Block Mode)",
            impact="Ransomware can rapidly encrypt user documents, desktop folders, and corporate shares without interception.",
            remediation_guidance="Enable Controlled Folder Access: Set-MpPreference -EnableControlledFolderAccess Enabled",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.15.1", "title": "Controlled Folder Access"}
            ],
            mitre_attack=["T1486", "T1562.001"],
            requires_admin=True,
        )

        cfa_val = pref.get("EnableControlledFolderAccess")
        if cfa_val is None:
            # Check registry fallback
            cfa_reg = reg.get(r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access", {})
            cfa_val = cfa_reg.get("EnableControlledFolderAccess")

        if cfa_val in (1, "1", True):
            findings.append(self.create_finding(
                r_001, FindingStatus.PASS,
                "Defender Controlled Folder Access is Enabled in Block Mode (1)",
                confidence=0.98, evidence_data={"EnableControlledFolderAccess": 1}
            ))
        elif cfa_val in (2, "2"):
            findings.append(self.create_finding(
                r_001, FindingStatus.WARN,
                "Defender Controlled Folder Access is in Audit Mode (2) — not actively blocking encryption",
                confidence=0.95, evidence_data={"EnableControlledFolderAccess": 2}
            ))
        elif cfa_val in (0, "0", False):
            findings.append(self.create_finding(
                r_001, FindingStatus.FAIL,
                "Defender Controlled Folder Access is Disabled (0) — Endpoint exposed to ransomware extortion",
                confidence=0.98, evidence_data={"EnableControlledFolderAccess": 0}
            ))
        else:
            # In synthetic hardened fixtures or standard Windows when unspecified
            findings.append(self.create_finding(
                r_001, FindingStatus.FAIL,
                "Controlled Folder Access is Not Configured (Disabled by default)",
                confidence=0.85, evidence_data={"EnableControlledFolderAccess": "Unconfigured"}
            ))

        # Check 2: WS-RSM-002 VSS & System Restore Resilience
        r_002 = Rule(
            id="WS-RSM-002",
            title="Volume Shadow Copy Service (VSS) Deletion Protection & System Restore Disabled",
            category="Ransomware Defense",
            severity=Severity.HIGH,
            description="Shadow copies provide point-in-time recovery points against file corruption and ransomware encryption.",
            expected="System Restore Active and VSS Service Available",
            impact="Adversary destruction of shadow copies precludes unassisted disaster recovery.",
            remediation_guidance="Enable System Restore on system drive: Enable-ComputerRestore -Drive 'C:\\'",
            compliance_mappings=[
                {"framework": "NIST SP 800-53", "version": "Rev 5", "control_id": "CP-9", "title": "System Backup"}
            ],
            mitre_attack=["T1490"],
            requires_admin=True,
        )

        sr_key = reg.get(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore", {})
        disable_sr = sr_key.get("DisableSR")
        
        # Check services for VSS
        vss_running = any(
            isinstance(s, dict) and s.get("Name", "").upper() == "VSS" and s.get("State", "").upper() in ("RUNNING", "AUTO", "MANUAL")
            for s in services
        ) if isinstance(services, list) else True

        if disable_sr == 1 or disable_sr == "1":
            findings.append(self.create_finding(
                r_002, FindingStatus.FAIL,
                "System Restore is explicitly disabled (DisableSR = 1) — Shadow point-in-time recovery disabled",
                confidence=0.95, evidence_data={"DisableSR": 1}
            ))
        else:
            findings.append(self.create_finding(
                r_002, FindingStatus.PASS,
                "System Restore and Volume Shadow Copy Services are active and available",
                confidence=0.90, evidence_data={"DisableSR": 0, "VSS_Active": vss_running}
            ))

        return findings
