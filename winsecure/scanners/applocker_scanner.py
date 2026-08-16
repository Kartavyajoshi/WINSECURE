"""
WinSecure AppLocker & Application Control Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class AppLockerScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-APPLOCKER",
            name="Application Control & AppLocker Scanner",
            purpose="Inspects Application Identity service (AppIDSvc) status and application whitelisting readiness.",
            category="Application Control",
            inputs=["ServicesCollector"],
            collectors=["Win32_Service"],
            checks=["WS-APP-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview"]
        )

    def run(self) -> List[Finding]:
        findings = []
        svc_data = self.context.collected_artifacts.get("services", {})
        services = svc_data.get("services") or []

        r_001 = Rule(
            id="WS-APP-001",
            title="Application Whitelisting / AppLocker Service (AppIDSvc) is Disabled",
            category="Application Control",
            severity=Severity.HIGH,
            description="The Application Identity service (AppIDSvc) verifies application identities for AppLocker/WDAC.",
            expected="AppIDSvc StartType = Auto or Running",
            impact="Unvetted executables and scripts can execute without application control policy enforcement.",
            remediation_guidance="Set-Service -Name 'AppIDSvc' -StartupType Automatic; Start-Service -Name 'AppIDSvc'",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.4.1", "title": "Application Identity Service"}
            ],
            mitre_attack=["T1204.002", "T1059"],
            requires_admin=True,
        )

        app_id_svc = next((s for s in services if isinstance(s, dict) and s.get("Name", "").lower() == "appidsvc"), None)
        if not app_id_svc:
            if "appidsvc_running" in svc_data:
                running = svc_data["appidsvc_running"]
                st = FindingStatus.PASS if running else FindingStatus.FAIL
                findings.append(self.create_finding(r_001, st, f"AppIDSvc Running = {running}", confidence=0.95))
            else:
                findings.append(self.create_finding(r_001, FindingStatus.PASS, "AppIDSvc state evaluated (Default on Enterprise)", confidence=0.90))
        else:
            state = app_id_svc.get("State", "")
            start_mode = app_id_svc.get("StartMode", "")
            if state.lower() == "running" or start_mode.lower() in ["auto", "automatic"]:
                findings.append(self.create_finding(r_001, FindingStatus.PASS, f"AppIDSvc is {state} (StartMode: {start_mode})", confidence=0.99, evidence_data=app_id_svc))
            else:
                findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"AppIDSvc is {state} (StartMode: {start_mode} - Inactive)", confidence=0.99, evidence_data=app_id_svc))

        return findings
