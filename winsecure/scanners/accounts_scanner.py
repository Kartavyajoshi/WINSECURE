"""
WinSecure Local Accounts Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class AccountsScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-ACCOUNTS",
            name="Local Accounts & Password Policy Scanner",
            purpose="Inspects local users, Guest account status, Administrator account protection, and password lockout policies.",
            category="Accounts",
            inputs=["AccountsCollector"],
            collectors=["Get-LocalUser", "Get-LocalGroupMember", "net accounts"],
            checks=["WS-ACC-001", "WS-ACC-002", "WS-ACC-003"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts"]
        )

    def run(self) -> List[Finding]:
        findings = []
        acc_data = self.context.collected_artifacts.get("accounts", {})
        users = acc_data.get("Users") or []
        if isinstance(users, dict):
            users = [users]

        user_map = {u.get("Name", "").lower(): u for u in users if isinstance(u, dict)}

        # 1. Guest Account Status (WS-ACC-001)
        r_001 = Rule(
            id="WS-ACC-001",
            title="Built-in Guest Account is Enabled",
            category="Accounts",
            severity=Severity.HIGH,
            description="The built-in Guest account allows unauthenticated access.",
            expected="Guest Account Enabled = False",
            impact="Anonymous users or network attackers can authenticate without a password.",
            remediation_guidance="Disable Guest account: Disable-LocalUser -Name 'Guest'",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "2.3.1.1", "title": "Guest Account Status"}
            ],
            mitre_attack=["T1078.001"],
            requires_admin=True,
        )
        guest = user_map.get("guest")
        if not guest:
            # Check if we have fixture or net accounts fallback
            if "guest_disabled" in acc_data:
                g_dis = acc_data["guest_disabled"]
                status = FindingStatus.PASS if g_dis else FindingStatus.FAIL
                findings.append(self.create_finding(r_001, status, f"Guest Disabled = {g_dis}", confidence=0.95))
            else:
                findings.append(self.create_finding(r_001, FindingStatus.PASS, "Guest account not present or inactive", confidence=0.90))
        else:
            is_enabled = guest.get("Enabled", False)
            if is_enabled is True or is_enabled == 1 or is_enabled == "True":
                findings.append(self.create_finding(r_001, FindingStatus.FAIL, "Built-in Guest account is Enabled (Active)", confidence=0.99, evidence_data=guest))
            else:
                findings.append(self.create_finding(r_001, FindingStatus.PASS, "Built-in Guest account is Disabled", confidence=0.99, evidence_data=guest))

        # 2. Administrator Account Status (WS-ACC-002)
        r_002 = Rule(
            id="WS-ACC-002",
            title="Built-in Administrator Account is Active Without Renaming",
            category="Accounts",
            severity=Severity.MEDIUM,
            description="The well-known Administrator account is targeted by automated brute-force attacks.",
            expected="Administrator Account disabled or renamed",
            impact="Attackers can brute-force the known RID 500 administrator account.",
            remediation_guidance="Disable-LocalUser -Name 'Administrator'",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "2.3.1.2", "title": "Administrator Account Status"}
            ],
            mitre_attack=["T1078.001"],
            requires_admin=True,
        )
        admin = user_map.get("administrator")
        if not admin:
            findings.append(self.create_finding(r_002, FindingStatus.PASS, "Built-in Administrator renamed or absent", confidence=0.90))
        else:
            is_enabled = admin.get("Enabled", False)
            if is_enabled is True or is_enabled == 1 or is_enabled == "True":
                findings.append(self.create_finding(r_002, FindingStatus.FAIL, "Built-in Administrator is Enabled with default name", confidence=0.95, evidence_data=admin))
            else:
                findings.append(self.create_finding(r_002, FindingStatus.PASS, "Built-in Administrator account is Disabled", confidence=0.99, evidence_data=admin))

        # 3. Lockout Policy (WS-ACC-003)
        r_003 = Rule(
            id="WS-ACC-003",
            title="Account Lockout Threshold is Not Configured",
            category="Accounts",
            severity=Severity.HIGH,
            description="Account lockout threshold limits consecutive failed logon attempts.",
            expected="Lockout threshold between 3 and 5 failed attempts",
            impact="Attackers can conduct unlimited password guessing without lockout.",
            remediation_guidance="net accounts /lockoutthreshold:5",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "1.2.1", "title": "Account Lockout Threshold"}
            ],
            mitre_attack=["T1110.001"],
            requires_admin=True,
        )
        net_raw = acc_data.get("net_accounts_raw", "")
        threshold = acc_data.get("lockout_threshold")
        if threshold is None:
            if "Lockout threshold:" in net_raw:
                for line in net_raw.splitlines():
                    if "Lockout threshold" in line:
                        parts = line.split(":")
                        if len(parts) > 1:
                            val_str = parts[1].strip()
                            if "Never" in val_str:
                                threshold = 0
                            else:
                                try:
                                    threshold = int(val_str.split()[0])
                                except Exception:
                                    threshold = 0
        if threshold is None:
            findings.append(self.create_finding(r_003, FindingStatus.UNKNOWN, "Lockout threshold could not be evaluated", confidence=0.5))
        elif threshold == 0 or threshold > 10:
            findings.append(self.create_finding(r_003, FindingStatus.FAIL, f"Lockout threshold = {threshold} (Never or too high)", confidence=0.95, evidence_data={"threshold": threshold}))
        else:
            findings.append(self.create_finding(r_003, FindingStatus.PASS, f"Lockout threshold = {threshold} attempts (Configured)", confidence=0.95, evidence_data={"threshold": threshold}))

        return findings
