"""
WinSecure Privileges Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class PrivilegesScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-PRIVILEGES",
            name="User Rights & Privileges Scanner",
            purpose="Assesses administrative memberships, excessive privilege assignments, and dangerous rights.",
            category="Privileges",
            inputs=["AccountsCollector"],
            collectors=["Get-LocalGroupMember 'Administrators'"],
            checks=["WS-PRIV-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/user-rights-assignment"]
        )

    def run(self) -> List[Finding]:
        findings = []
        acc_data = self.context.collected_artifacts.get("accounts", {})
        admins = acc_data.get("Administrators") or []
        if isinstance(admins, dict):
            admins = [admins]

        r_001 = Rule(
            id="WS-PRIV-001",
            title="Excessive Local Administrators Detected",
            category="Privileges",
            severity=Severity.MEDIUM,
            description="Local Administrator group should only contain designated IT administration accounts.",
            expected="Local Administrators count <= 2",
            impact="Excessive administrative accounts expand attack surface and credential exposure.",
            remediation_guidance="Remove unnecessary users: Remove-LocalGroupMember -Group 'Administrators' -Member <username>",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "2.2.1", "title": "Local Administrator Membership"}
            ],
            mitre_attack=["T1078.003"],
            requires_admin=True,
        )

        admin_count = len(admins) if admins else acc_data.get("admin_count", 1)
        if admin_count > 3:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"Detected {admin_count} local administrators (Threshold: 2)", confidence=0.95, evidence_data=admins))
        elif admin_count > 2:
            findings.append(self.create_finding(r_001, FindingStatus.WARN, f"Detected {admin_count} local administrators (Review recommended)", confidence=0.90, evidence_data=admins))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, f"Local administrators count is {admin_count} (Within limits)", confidence=0.95, evidence_data=admins))

        return findings
