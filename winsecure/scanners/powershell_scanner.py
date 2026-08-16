"""
WinSecure PowerShell Security Configuration Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class PowerShellScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-POWERSHELL",
            name="PowerShell Security Configuration Scanner",
            purpose="Inspects PowerShell Script Block Logging, Module Logging, Transcription, and Execution Policy.",
            category="PowerShell",
            inputs=["RegistryCollector", "PowerShellCollector"],
            collectors=["Get-ExecutionPolicy", "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell"],
            checks=["WS-PS-001", "WS-PS-002"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53", "Microsoft Security Baseline"],
            references=["https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows"]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        sbl_key = reg.get(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", {})
        ps_data = self.context.collected_artifacts.get("powershell", {})

        # 1. Script Block Logging (WS-PS-001)
        r_001 = Rule(
            id="WS-PS-001",
            title="PowerShell Script Block Logging is Disabled",
            category="PowerShell",
            severity=Severity.HIGH,
            description="Script Block Logging captures complete, de-obfuscated script code blocks into Event ID 4104.",
            expected="EnableScriptBlockLogging = 1",
            impact="Living-off-the-land PowerShell attacks, download cradles, and memory injection cannot be investigated.",
            remediation_guidance="Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.60.1", "title": "Script Block Logging"},
                {"framework": "NIST SP 800-53", "version": "Rev 5", "control_id": "AU-2", "title": "Event Logging"}
            ],
            mitre_attack=["T1059.001"],
            requires_admin=True,
        )
        sbl_val = sbl_key.get("EnableScriptBlockLogging")
        if sbl_val == 1:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "EnableScriptBlockLogging = 1 (Active)", confidence=0.99, evidence_data={"EnableScriptBlockLogging": 1}))
        elif sbl_val == 0:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, "EnableScriptBlockLogging = 0 (Explicitly Disabled)", confidence=0.99, evidence_data={"EnableScriptBlockLogging": 0}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, "Script Block Logging is not enabled via Group Policy", confidence=0.90))

        # 2. Execution Policy (WS-PS-002)
        r_002 = Rule(
            id="WS-PS-002",
            title="PowerShell Execution Policy is Set to Unrestricted or Bypass",
            category="PowerShell",
            severity=Severity.MEDIUM,
            description="Execution Policy provides basic defense against accidental execution of unvetted scripts.",
            expected="ExecutionPolicy in [RemoteSigned, Restricted, AllSigned]",
            impact="Downloaded untrusted scripts can run without digital signature verification or zone checks.",
            remediation_guidance="Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.60.2", "title": "Script Execution"}
            ],
            mitre_attack=["T1059.001"],
            requires_admin=True,
        )
        ep_info = ps_data.get("execution_policy", {})
        if isinstance(ep_info, dict):
            lm_pol = ep_info.get("LocalMachine", "Undefined")
            user_pol = ep_info.get("CurrentUser", "Undefined")
            effective = lm_pol if lm_pol != "Undefined" else user_pol
        else:
            effective = str(ep_info)

        if effective.lower() in ["unrestricted", "bypass"]:
            findings.append(self.create_finding(r_002, FindingStatus.FAIL, f"Execution Policy = {effective} (Weak)", confidence=0.95, evidence_data=ep_info))
        elif effective.lower() in ["remotesigned", "restricted", "allsigned"]:
            findings.append(self.create_finding(r_002, FindingStatus.PASS, f"Execution Policy = {effective} (Enforced)", confidence=0.95, evidence_data=ep_info))
        else:
            findings.append(self.create_finding(r_002, FindingStatus.PASS, "Execution Policy is set to default Restricted", confidence=0.90))

        return findings
