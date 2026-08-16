"""
WinSecure Audit Policy Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class AuditScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-AUDIT",
            name="Windows Audit Policy Security Scanner",
            purpose="Inspects process creation auditing, command line parameter auditing, logon/logoff events, and system audit policies.",
            category="Audit Policy",
            inputs=["AuditCollector", "RegistryCollector"],
            collectors=["auditpol.exe /get /category:* /r", "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"],
            checks=["WS-AUD-001", "WS-AUD-002", "WS-AUD-003"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53", "DISA STIG"],
            references=["https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing-faq"]
        )

    def run(self) -> List[Finding]:
        findings = []
        audit_data = self.context.collected_artifacts.get("audit", {})
        subcats = audit_data.get("subcategories") or {}
        reg = self.context.collected_artifacts.get("registry", {})
        audit_reg = reg.get(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", {})

        # 1. Process Creation (WS-AUD-001)
        r_001 = Rule(
            id="WS-AUD-001",
            title="Process Creation Auditing is Not Configured",
            category="Audit Policy",
            severity=Severity.HIGH,
            description="Auditing process creation events (Event ID 4688) records program executions.",
            expected="Process Creation Audit = Success and Failure",
            impact="Malicious binary execution cannot be traced during forensics investigations.",
            remediation_guidance="auditpol /set /subcategory:'Process Creation' /success:enable /failure:enable",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "17.2.1", "title": "Audit Process Creation"}
            ],
            mitre_attack=["T1059"],
            requires_admin=True,
        )
        proc_audit = subcats.get("Process Creation", {}).get("setting", "")
        if "success" in proc_audit.lower():
            findings.append(self.create_finding(r_001, FindingStatus.PASS, f"Process Creation setting = '{proc_audit}'", confidence=0.99, evidence_data={"setting": proc_audit}))
        elif proc_audit:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"Process Creation setting = '{proc_audit}' (Incomplete)", confidence=0.99, evidence_data={"setting": proc_audit}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, "Process Creation audit policy is disabled or unconfigured", confidence=0.90))

        # 2. Command Line Auditing (WS-AUD-002)
        r_002 = Rule(
            id="WS-AUD-002",
            title="Process Command-Line Auditing is Disabled",
            category="Audit Policy",
            severity=Severity.HIGH,
            description="Including process command lines in Event 4688 records CLI parameters passed to interpreters.",
            expected="ExecutionProcessCommandLine = 1",
            impact="Living-off-the-land attacks hiding payloads inside CLI flags remain invisible.",
            remediation_guidance="Set ProcessCreationIncludeCmdLine_Enabled to 1 in HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.4.1", "title": "Command Line Auditing"}
            ],
            mitre_attack=["T1059"],
            requires_admin=True,
        )
        cmd_line_val = audit_reg.get("ProcessCreationIncludeCmdLine_Enabled")
        if cmd_line_val == 1:
            findings.append(self.create_finding(r_002, FindingStatus.PASS, "ProcessCreationIncludeCmdLine_Enabled = 1 (Active)", confidence=0.99, evidence_data={"ProcessCreationIncludeCmdLine_Enabled": 1}))
        else:
            findings.append(self.create_finding(r_002, FindingStatus.FAIL, f"ProcessCreationIncludeCmdLine_Enabled = {cmd_line_val or 0} (Disabled)", confidence=0.99, evidence_data={"ProcessCreationIncludeCmdLine_Enabled": cmd_line_val}))

        # 3. Logon Auditing (WS-AUD-003)
        r_003 = Rule(
            id="WS-AUD-003",
            title="Logon and Logoff Auditing is Incomplete",
            category="Audit Policy",
            severity=Severity.HIGH,
            description="Auditing logon attempts (Event 4624/4625) provides detection for unauthorized intrusions.",
            expected="Logon Audit = Success and Failure",
            impact="Failed authentication attacks occur silently.",
            remediation_guidance="auditpol /set /subcategory:'Logon' /success:enable /failure:enable",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "17.5.1", "title": "Audit Logon"}
            ],
            mitre_attack=["T1078"],
            requires_admin=True,
        )
        logon_audit = subcats.get("Logon", {}).get("setting", "")
        if "success" in logon_audit.lower() and "failure" in logon_audit.lower():
            findings.append(self.create_finding(r_003, FindingStatus.PASS, f"Logon audit setting = '{logon_audit}' (Complete)", confidence=0.99, evidence_data={"setting": logon_audit}))
        elif "success" in logon_audit.lower():
            findings.append(self.create_finding(r_003, FindingStatus.WARN, f"Logon audit setting = '{logon_audit}' (Missing Failure audit)", confidence=0.95, evidence_data={"setting": logon_audit}))
        else:
            findings.append(self.create_finding(r_003, FindingStatus.FAIL, f"Logon audit setting = '{logon_audit or 'No Auditing'}'", confidence=0.95, evidence_data={"setting": logon_audit}))

        return findings
