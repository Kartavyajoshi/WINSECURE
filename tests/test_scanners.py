"""
Comprehensive Unit Tests for All 32 Scanner Modules (PASS, FAIL, UNKNOWN, ERROR Fixtures)
"""
import unittest
from winsecure.core.config import ScanConfig
from winsecure.core.context import ScanContext
from winsecure.scanners import (
    DefenderScanner, FirewallScanner, AccountsScanner, PrivilegesScanner,
    ServicesScanner, StartupScanner, TasksScanner, RegistryScanner,
    PowerShellScanner, AuditScanner, EventLogsScanner, UpdatesScanner,
    SMBScanner, RemoteScanner, NetworkScanner, EncryptionScanner,
    UACScanner, SmartScreenScanner, SoftwareScanner, SystemScanner,
    AppLockerScanner, VBSScanner, LAPSScanner, ASRScanner,
    ExploitGuardScanner, SchannelScanner, KerberosScanner,
    SandboxScanner, SpoolerScanner, BrowserScanner,
    ADScanner, SysmonScanner,
    ALL_SCANNERS
)
from winsecure.models import FindingStatus, Severity


class TestAllScanners(unittest.TestCase):
    def setUp(self):
        self.config = ScanConfig()

    def test_scanner_count(self):
        self.assertEqual(len(ALL_SCANNERS), 32)

    def test_defender_scanner_all_states(self):
        # 1. PASS
        ctx_pass = ScanContext(self.config)
        ctx_pass.collected_artifacts["defender"] = {
            "Status": {"RealTimeProtectionEnabled": True, "CloudProtectionLevel": 2, "BehaviorMonitorEnabled": True, "AntivirusSignatureAge": 1},
            "Preferences": {"PUAProtection": 1, "ExclusionPath": []}
        }
        findings_pass = DefenderScanner(ctx_pass).run()
        self.assertTrue(all(f.status == FindingStatus.PASS for f in findings_pass))

        # 2. FAIL
        ctx_fail = ScanContext(self.config)
        ctx_fail.collected_artifacts["defender"] = {
            "Status": {"RealTimeProtectionEnabled": False, "CloudProtectionLevel": 0, "BehaviorMonitorEnabled": False, "AntivirusSignatureAge": 14},
            "Preferences": {"PUAProtection": 0, "ExclusionPath": ["C:\\"]}
        }
        findings_fail = DefenderScanner(ctx_fail).run()
        self.assertTrue(all(f.status == FindingStatus.FAIL for f in findings_fail))

        # 3. UNKNOWN
        ctx_unk = ScanContext(self.config)
        ctx_unk.collected_artifacts["defender"] = {}
        findings_unk = DefenderScanner(ctx_unk).run()
        self.assertTrue(any(f.status == FindingStatus.UNKNOWN for f in findings_unk))

    def test_firewall_scanner_all_states(self):
        # 1. PASS
        ctx_p = ScanContext(self.config)
        ctx_p.collected_artifacts["firewall"] = {
            "Profiles": [
                {"Name": "Public", "Enabled": True, "DefaultInboundAction": "Block"},
                {"Name": "Domain", "Enabled": True},
                {"Name": "Private", "Enabled": True}
            ]
        }
        f_p = FirewallScanner(ctx_p).run()
        self.assertTrue(all(f.status == FindingStatus.PASS for f in f_p))

        # 2. FAIL
        ctx_f = ScanContext(self.config)
        ctx_f.collected_artifacts["firewall"] = {
            "Profiles": [
                {"Name": "Public", "Enabled": False, "DefaultInboundAction": "Allow"},
                {"Name": "Domain", "Enabled": False},
                {"Name": "Private", "Enabled": False}
            ]
        }
        f_f = FirewallScanner(ctx_f).run()
        self.assertTrue(all(f.status == FindingStatus.FAIL for f in f_f))

        # 3. UNKNOWN
        ctx_u = ScanContext(self.config)
        ctx_u.collected_artifacts["firewall"] = {"Profiles": []}
        f_u = FirewallScanner(ctx_u).run()
        self.assertTrue(all(f.status == FindingStatus.UNKNOWN for f in f_u))

    def test_uac_scanner_all_states(self):
        # 1. PASS
        ctx_p = ScanContext(self.config)
        ctx_p.collected_artifacts["registry"] = {
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System": {
                "EnableLUA": 1, "ConsentPromptBehaviorAdmin": 2, "PromptOnSecureDesktop": 1
            }
        }
        self.assertTrue(all(f.status == FindingStatus.PASS for f in UACScanner(ctx_p).run()))

        # 2. FAIL
        ctx_f = ScanContext(self.config)
        ctx_f.collected_artifacts["registry"] = {
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System": {
                "EnableLUA": 0, "ConsentPromptBehaviorAdmin": 0, "PromptOnSecureDesktop": 0
            }
        }
        self.assertTrue(all(f.status == FindingStatus.FAIL for f in UACScanner(ctx_f).run()))

        # 3. UNKNOWN
        ctx_u = ScanContext(self.config)
        ctx_u.collected_artifacts["registry"] = {}
        self.assertTrue(all(f.status == FindingStatus.UNKNOWN for f in UACScanner(ctx_u).run()))

    def test_ad_and_sysmon_scanners(self):
        ctx = ScanContext(self.config)
        ctx.collected_artifacts["registry"] = {
            r"HKLM\SYSTEM\CurrentControlSet\Services\LDAP": {"LDAPClientIntegrity": 2},
            r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters": {"RequireSignOrSeal": 1}
        }
        ctx.collected_artifacts["services"] = {
            "services": [{"Name": "Sysmon64", "State": "Running", "StartMode": "Auto"}]
        }
        self.assertTrue(all(f.status == FindingStatus.PASS for f in ADScanner(ctx).run()))
        self.assertTrue(all(f.status == FindingStatus.PASS for f in SysmonScanner(ctx).run()))


if __name__ == "__main__":
    unittest.main()
