"""
WinSecure Windows Update Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class UpdatesScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-UPDATES",
            name="Windows Update & Servicing State Scanner",
            purpose="Inspects pending reboots, recent security hotfixes, and update servicing state.",
            category="Updates",
            inputs=["UpdatesCollector"],
            collectors=["Get-HotFix", "Microsoft.Update.Session"],
            checks=["WS-UPD-001"],
            requires_admin=False,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows/deployment/update/"]
        )

    def run(self) -> List[Finding]:
        findings = []
        upd_data = self.context.collected_artifacts.get("updates", {})
        pending_reboot = upd_data.get("PendingReboot", False)

        r_001 = Rule(
            id="WS-UPD-001",
            title="Pending System Reboot Required for Security Updates",
            category="Updates",
            severity=Severity.MEDIUM,
            description="Pending reboots indicate installed security patches have not yet taken effect.",
            expected="PendingReboot = False",
            impact="System remains vulnerable to patched exploits until restarted.",
            remediation_guidance="Restart-Computer",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.1", "title": "Automatic Updates"}
            ],
            mitre_attack=["T1190"],
            requires_admin=False,
        )

        if pending_reboot:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, "System has pending reboot for installed updates", confidence=0.99, evidence_data=upd_data))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "No pending reboot required for security updates", confidence=0.95))

        return findings
