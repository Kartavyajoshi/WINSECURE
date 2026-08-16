"""
WinSecure Event Logs Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class EventLogsScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-EVENTLOGS",
            name="Windows Event Log Infrastructure Scanner",
            purpose="Inspects Security, System, and PowerShell operational event log size, retention, and enablement.",
            category="Event Logs",
            inputs=["EventLogCollector"],
            collectors=["Get-WinEvent -ListLog"],
            checks=["WS-EVT-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-help-with-intrusion-detection"]
        )

    def run(self) -> List[Finding]:
        findings = []
        evt_data = self.context.collected_artifacts.get("eventlogs", {})
        sec_log = evt_data.get("Security") or {}

        r_001 = Rule(
            id="WS-EVT-001",
            title="Security Event Log Maximum Size Insufficient (< 1GB)",
            category="Event Logs",
            severity=Severity.MEDIUM,
            description="The Windows Security log size must be configured to at least 1,048,576 KB (1 GB) to prevent log wrapping.",
            expected="MaximumSizeInBytes >= 1073741824 bytes (1024 MB)",
            impact="High event volume during an incident will overwrite older evidence before collection.",
            remediation_guidance="Limit-EventLog -LogName Security -MaximumSize 1GB",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.14.1", "title": "Security Log Size"}
            ],
            mitre_attack=["T1562.002"],
            requires_admin=True,
        )

        max_size = sec_log.get("MaximumSizeInBytes")
        if max_size is None:
            findings.append(self.create_finding(r_001, FindingStatus.UNKNOWN, "Security log properties could not be queried", confidence=0.5))
        elif max_size >= 1073741824:
            mb = round(max_size / (1024 * 1024), 1)
            findings.append(self.create_finding(r_001, FindingStatus.PASS, f"Security log maximum size = {mb} MB (>= 1 GB)", confidence=0.99, evidence_data=sec_log))
        else:
            mb = round(max_size / (1024 * 1024), 1)
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"Security log maximum size = {mb} MB (< 1024 MB)", confidence=0.99, evidence_data=sec_log))

        return findings
