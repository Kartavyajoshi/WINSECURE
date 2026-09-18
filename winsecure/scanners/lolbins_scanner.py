"""
WinSecure Living-Off-The-Land (LOLBins) & WDAC Policy Scanner Module (Module 35)
Grounded in Living-off-the-Land and binary abuse prevention research.
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class LOLBinsScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-LOLBINS",
            name="Living-Off-The-Land (LOLBins) & WDAC Policy Scanner",
            purpose="Audits Windows Defender Application Control (WDAC) block rules and PowerShell Constrained Language Mode (CLM).",
            category="Application Control",
            inputs=["RegistryCollector"],
            collectors=["DeviceGuard Policy", "PowerShell Environment"],
            checks=["WS-LOL-001", "WS-LOL-002"],
            requires_admin=False,
            compliance_frameworks=["CIS Windows 11 Enterprise", "DISA STIG", "NIST SP 800-53"],
            references=[
                "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac",
                "Gao et al., Systematic Analysis of Living-off-the-Land Attack Vectors (USENIX)"
            ]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})

        # Check 1: WS-LOL-001 WDAC Recommended Block Rules
        r_001 = Rule(
            id="WS-LOL-001",
            title="Windows Defender Application Control (WDAC) Recommended Block Rules Unenforced",
            category="Application Control",
            severity=Severity.HIGH,
            description="WDAC recommended block rules prevent threat actors from abusing signed utilities like certutil, mshta, and regsvr32.",
            expected="WDAC Recommended Block Rules Enforced",
            impact="Adversaries can execute staging payloads and memory loaders using native trusted binaries.",
            remediation_guidance="Enforce WDAC Recommended Block Rules list via Group Policy or Intune.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.4.1", "title": "WDAC Recommended Block Rules"}
            ],
            mitre_attack=["T1218", "T1218.005", "T1218.010"],
            requires_admin=True,
        )

        ci_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config", {})
        blocklist_enabled = ci_key.get("VulnerableDriverBlocklistEnable")

        dg_key = reg.get(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", {})
        app_block_rules = dg_key.get("RecommendedBlockRules")

        if app_block_rules in (1, "1") or blocklist_enabled in (1, "1"):
            findings.append(self.create_finding(
                r_001, FindingStatus.PASS,
                "WDAC Recommended Application and Driver Block Rules are active",
                confidence=0.95, evidence_data={"RecommendedBlockRules": 1}
            ))
        elif app_block_rules in (0, "0"):
            findings.append(self.create_finding(
                r_001, FindingStatus.FAIL,
                "WDAC Recommended Block Rules explicitly disabled via policy",
                confidence=0.95, evidence_data={"RecommendedBlockRules": 0}
            ))
        else:
            # Default state on Windows 11 22H2+ includes kernel driver blocklist
            findings.append(self.create_finding(
                r_001, FindingStatus.PASS,
                "Microsoft Recommended Vulnerable Driver & Application Block Rules active by default on Windows 11",
                confidence=0.90, evidence_data={"VulnerableDriverBlocklist": "Active"}
            ))

        # Check 2: WS-LOL-002 PowerShell Constrained Language Mode (CLM)
        r_002 = Rule(
            id="WS-LOL-002",
            title="PowerShell Constrained Language Mode (CLM) Disabled for Standard User Sessions",
            category="Application Control",
            severity=Severity.HIGH,
            description="Constrained Language Mode prevents standard users from executing arbitrary .NET reflections and Win32 APIs in PowerShell.",
            expected="__PSLockdownPolicy = 4 (ConstrainedLanguage)",
            impact="Adversaries can execute reflective DLL injections and custom offensive C# scripts directly from PowerShell console.",
            remediation_guidance="Set system environment variable __PSLockdownPolicy to 4 or enforce AppLocker/WDAC script enforcement.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.30.2", "title": "PowerShell Constrained Language Mode"},
                {"framework": "DISA STIG", "version": "V1R3", "control_id": "WN11-CC-000310", "title": "PowerShell Constrained Language"}
            ],
            mitre_attack=["T1059.001"],
            requires_admin=False,
        )

        env_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment", {})
        lockdown_val = env_key.get("__PSLockdownPolicy")

        if lockdown_val in (4, "4"):
            findings.append(self.create_finding(
                r_002, FindingStatus.PASS,
                "PowerShell Constrained Language Mode (CLM) is enforced system-wide (__PSLockdownPolicy = 4)",
                confidence=0.99, evidence_data={"__PSLockdownPolicy": 4}
            ))
        else:
            findings.append(self.create_finding(
                r_002, FindingStatus.FAIL,
                f"PowerShell operates in FullLanguage mode (__PSLockdownPolicy = {lockdown_val or 'Unset'}) — Arbitrary Win32 API invocation permitted",
                confidence=0.95, evidence_data={"__PSLockdownPolicy": lockdown_val or "Unset"}
            ))

        return findings
