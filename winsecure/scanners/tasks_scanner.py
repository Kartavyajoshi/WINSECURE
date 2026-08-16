"""
WinSecure Scheduled Tasks Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class TasksScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-TASKS",
            name="Scheduled Tasks Security Scanner",
            purpose="Inspects scheduled tasks for execution from user-writable directories, unusual task actions, and persistence.",
            category="Scheduled Tasks",
            inputs=["TasksCollector"],
            collectors=["schtasks.exe /query /fo csv /v"],
            checks=["WS-TSK-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler"]
        )

    def run(self) -> List[Finding]:
        findings = []
        tasks_data = self.context.collected_artifacts.get("tasks", {})
        task_list = tasks_data.get("tasks") or []

        r_001 = Rule(
            id="WS-TSK-001",
            title="Scheduled Task Executing from User-Writable Temp Directory",
            category="Scheduled Tasks",
            severity=Severity.HIGH,
            description="Scheduled tasks executing binaries from %TEMP%, %APPDATA%, or %PUBLIC% represent potential persistence or privilege escalation.",
            expected="Tasks execute from protected system directories (C:\\Windows, C:\\Program Files)",
            impact="Adversaries can overwrite or plant malicious payloads triggered on scheduled task runs.",
            remediation_guidance="Inspect and reconfigure task actions using Task Scheduler (taskschd.msc).",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.2", "title": "Scheduled Task Integrity"}
            ],
            mitre_attack=["T1053.005"],
            requires_admin=True,
        )

        suspicious_tasks = []
        for t in task_list:
            if not isinstance(t, dict):
                continue
            act = str(t.get("action", "")).lower()
            if any(p in act for p in ["\\temp\\", "\\appdata\\local\\temp", "\\users\\public"]):
                suspicious_tasks.append(t)

        if suspicious_tasks:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"Detected {len(suspicious_tasks)} tasks executing from user-writable paths", confidence=0.95, evidence_data=suspicious_tasks))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "No scheduled tasks executing from user-writable paths", confidence=0.95))

        return findings
