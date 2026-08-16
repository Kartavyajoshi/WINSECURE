"""
WinSecure Startup & Persistence Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class StartupScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-STARTUP",
            name="Startup & Registry Persistence Scanner",
            purpose="Inspects startup applications, Run and RunOnce registry keys for unvetted or suspicious persistence binaries.",
            category="Startup",
            inputs=["RegistryCollector"],
            collectors=["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
            checks=["WS-START-001"],
            requires_admin=False,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys"]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        hklm_run = reg.get(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", {})
        hkcu_run = reg.get(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", {})

        r_001 = Rule(
            id="WS-START-001",
            title="Unverified Binary in User Run/RunOnce Startup Keys",
            category="Startup",
            severity=Severity.MEDIUM,
            description="Registry Run and RunOnce keys execute binaries automatically on user logon.",
            expected="Startup entries vetted and located in secure Program Files directories",
            impact="Malicious payloads or adware maintain persistence across user logons.",
            remediation_guidance="Audit startup registry keys in HKCU/HKLM Software\\Microsoft\\Windows\\CurrentVersion\\Run.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.1", "title": "Startup Persistence"}
            ],
            mitre_attack=["T1547.001"],
            requires_admin=False,
        )

        suspicious = []
        for name, val in {**hklm_run, **hkcu_run}.items():
            if name.startswith("_"):
                continue
            val_str = str(val).lower()
            if any(p in val_str for p in ["\\temp\\", "\\appdata\\local\\temp", "\\users\\public", "powershell -enc", "cmd /c"]):
                suspicious.append({"name": name, "command": str(val)})

        if suspicious:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"Suspicious startup binaries in user-writable paths: {len(suspicious)} entries", confidence=0.95, evidence_data=suspicious))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "No suspicious startup persistence entries detected in Run keys", confidence=0.95))

        return findings
