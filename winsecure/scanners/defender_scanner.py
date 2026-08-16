"""
WinSecure Microsoft Defender Security Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class DefenderScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-DEFENDER",
            name="Microsoft Defender Security Scanner",
            purpose="Inspects Microsoft Defender antivirus configuration, real-time protection, cloud intelligence, behavior monitoring, PUA, and exclusion attack surfaces.",
            category="Defender",
            inputs=["DefenderCollector", "RegistryCollector"],
            collectors=["Get-MpComputerStatus", "Get-MpPreference"],
            checks=["WS-DEF-001", "WS-DEF-002", "WS-DEF-003", "WS-DEF-004", "WS-DEF-005", "WS-DEF-006"],
            requires_admin=True,
            admin_recommended=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53", "Microsoft Security Baseline"],
            references=["https://learn.microsoft.com/en-us/defender-endpoint/"]
        )

    def run(self) -> List[Finding]:
        findings = []
        defender_data = self.context.collected_artifacts.get("defender", {})
        status_info = defender_data.get("Status") or {}
        pref_info = defender_data.get("Preferences") or {}

        # 1. Real-Time Protection (WS-DEF-001)
        rule_001 = Rule(
            id="WS-DEF-001",
            title="Microsoft Defender Real-Time Protection is Disabled",
            category="Defender",
            severity=Severity.CRITICAL,
            description="Microsoft Defender Real-Time Protection monitors system activity and blocks malware pre-execution.",
            expected="RealTimeProtectionEnabled = True",
            impact="Malware and unauthorized binaries can execute without real-time interception.",
            remediation_guidance="Set-MpPreference -DisableRealtimeMonitoring $false",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.46.1", "title": "Real-Time Protection"},
                {"framework": "NIST SP 800-53", "version": "Rev 5", "control_id": "SI-3", "title": "Malicious Code Protection"},
            ],
            mitre_attack=["T1562.001"],
            requires_admin=True,
        )
        rtp_val = status_info.get("RealTimeProtectionEnabled")
        if rtp_val is None:
            findings.append(self.create_finding(rule_001, FindingStatus.UNKNOWN, "RealTimeProtection status could not be queried", confidence=0.5, evidence_data=defender_data))
        elif rtp_val is True or rtp_val == 1:
            findings.append(self.create_finding(rule_001, FindingStatus.PASS, "Real-Time Protection is actively enabled (True)", confidence=0.99, evidence_data={"RealTimeProtectionEnabled": True}))
        else:
            findings.append(self.create_finding(rule_001, FindingStatus.FAIL, f"RealTimeProtectionEnabled = {rtp_val} (Disabled)", confidence=0.99, evidence_data={"RealTimeProtectionEnabled": rtp_val}))

        # 2. Cloud Protection (WS-DEF-002)
        rule_002 = Rule(
            id="WS-DEF-002",
            title="Defender Cloud-Delivered Protection is Disabled",
            category="Defender",
            severity=Severity.HIGH,
            description="Cloud-delivered protection enables rapid cloud telemetry and machine learning detection.",
            expected="CloudProtectionLevel != 0 (Enabled)",
            impact="No cloud intelligence for rapid zero-day detection.",
            remediation_guidance="Set-MpPreference -MAPSReporting Advanced",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.46.2", "title": "Cloud Protection"}
            ],
            mitre_attack=["T1562.001"],
            requires_admin=True,
        )
        cloud_val = status_info.get("CloudProtectionLevel")
        if cloud_val is None:
            # Fallback to checking MAPS
            cloud_val = 1 if status_info.get("AntivirusEnabled") else None
        
        if cloud_val is None:
            findings.append(self.create_finding(rule_002, FindingStatus.UNKNOWN, "CloudProtectionLevel not determined", confidence=0.5))
        elif cloud_val == 0 or cloud_val is False:
            findings.append(self.create_finding(rule_002, FindingStatus.FAIL, f"CloudProtectionLevel = {cloud_val} (Disabled)", confidence=0.95, evidence_data={"CloudProtectionLevel": cloud_val}))
        else:
            findings.append(self.create_finding(rule_002, FindingStatus.PASS, f"CloudProtectionLevel = {cloud_val} (Enabled)", confidence=0.95, evidence_data={"CloudProtectionLevel": cloud_val}))

        # 3. Behavior Monitoring (WS-DEF-003)
        rule_003 = Rule(
            id="WS-DEF-003",
            title="Defender Behavior Monitoring is Disabled",
            category="Defender",
            severity=Severity.HIGH,
            description="Behavior monitoring tracks process heuristics and blocks suspicious process execution chains.",
            expected="BehaviorMonitorEnabled = True",
            impact="Evasive malware leveraging memory injection or living-off-the-land techniques may bypass static signatures.",
            remediation_guidance="Set-MpPreference -DisableBehaviorMonitoring $false",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.46.3", "title": "Behavior Monitoring"}
            ],
            mitre_attack=["T1562.001"],
            requires_admin=True,
        )
        bm_val = status_info.get("BehaviorMonitorEnabled")
        if bm_val is None:
            findings.append(self.create_finding(rule_003, FindingStatus.UNKNOWN, "BehaviorMonitorEnabled status not determined", confidence=0.5))
        elif bm_val is True or bm_val == 1:
            findings.append(self.create_finding(rule_003, FindingStatus.PASS, "BehaviorMonitorEnabled = True", confidence=0.99, evidence_data={"BehaviorMonitorEnabled": True}))
        else:
            findings.append(self.create_finding(rule_003, FindingStatus.FAIL, f"BehaviorMonitorEnabled = {bm_val} (Disabled)", confidence=0.99, evidence_data={"BehaviorMonitorEnabled": bm_val}))

        # 4. PUA Protection (WS-DEF-004)
        rule_004 = Rule(
            id="WS-DEF-004",
            title="Potentially Unwanted Application (PUA) Protection is Disabled",
            category="Defender",
            severity=Severity.MEDIUM,
            description="PUA protection blocks adware, crypto-miners, and unwanted bundlers that degrade system security.",
            expected="PUAProtection = 1 (Enabled)",
            impact="Users may inadvertently install greyware, keyloggers, or aggressive adware.",
            remediation_guidance="Set-MpPreference -PUAProtection 1",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.46.4", "title": "PUA Protection"}
            ],
            mitre_attack=["T1562.001"],
            requires_admin=True,
        )
        pua_val = pref_info.get("PUAProtection")
        if pua_val is None:
            findings.append(self.create_finding(rule_004, FindingStatus.UNKNOWN, "PUAProtection status not determined", confidence=0.5))
        elif pua_val in [1, True, "1", "Enabled"]:
            findings.append(self.create_finding(rule_004, FindingStatus.PASS, "PUAProtection = 1 (Enabled)", confidence=0.95, evidence_data={"PUAProtection": pua_val}))
        else:
            findings.append(self.create_finding(rule_004, FindingStatus.FAIL, f"PUAProtection = {pua_val} (Disabled)", confidence=0.95, evidence_data={"PUAProtection": pua_val}))

        # 5. Antivirus Signature Age (WS-DEF-005)
        rule_005 = Rule(
            id="WS-DEF-005",
            title="Antivirus Signature Definitions Outdated (> 7 Days)",
            category="Defender",
            severity=Severity.HIGH,
            description="Security intelligence definitions must be refreshed daily to protect against active threat campaigns.",
            expected="AntivirusSignatureAge <= 7 days",
            impact="The endpoint cannot detect recent malware variants identified in the past week.",
            remediation_guidance="Update Defender signatures via Update-MpSignature",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.46.5", "title": "Signature Age"}
            ],
            mitre_attack=["T1562.001"],
            requires_admin=False,
        )
        sig_age = status_info.get("AntivirusSignatureAge")
        if sig_age is None:
            findings.append(self.create_finding(rule_005, FindingStatus.UNKNOWN, "AntivirusSignatureAge not determined", confidence=0.5))
        elif isinstance(sig_age, (int, float)) and sig_age <= 7:
            findings.append(self.create_finding(rule_005, FindingStatus.PASS, f"AntivirusSignatureAge = {sig_age} days (Up to date)", confidence=0.99, evidence_data={"AntivirusSignatureAge": sig_age}))
        else:
            findings.append(self.create_finding(rule_005, FindingStatus.FAIL, f"AntivirusSignatureAge = {sig_age} days (Outdated > 7 days)", confidence=0.99, evidence_data={"AntivirusSignatureAge": sig_age}))

        # 6. Exclusions (WS-DEF-006)
        rule_006 = Rule(
            id="WS-DEF-006",
            title="Dangerous Antivirus Folder/Path Exclusions Detected",
            category="Defender",
            severity=Severity.HIGH,
            description="Broad folder exclusions (such as C:\\, C:\\Windows, C:\\Users, or %TEMP%) allow adversaries to drop and execute malware with zero AV scanning.",
            expected="No overly broad exclusions in ExclusionPath",
            impact="Adversaries staging payloads in excluded paths evade detection entirely.",
            remediation_guidance="Review and remove broad exclusions using Remove-MpPreference -ExclusionPath <path>",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.9.46.6", "title": "Exclusion Review"}
            ],
            mitre_attack=["T1562.001"],
            requires_admin=True,
        )
        exclusions = pref_info.get("ExclusionPath") or []
        if isinstance(exclusions, str):
            exclusions = [exclusions]
        
        dangerous = [e for e in exclusions if any(e.strip().lower().startswith(b) for b in ["c:\\", "c:\\users", "c:\\windows", "c:\\temp", "%temp%"])]
        if dangerous:
            findings.append(self.create_finding(rule_006, FindingStatus.FAIL, f"Dangerous broad exclusions found: {', '.join(dangerous)}", confidence=0.99, evidence_data={"ExclusionPath": exclusions}))
        else:
            findings.append(self.create_finding(rule_006, FindingStatus.PASS, "No overly broad exclusions detected", confidence=0.95, evidence_data={"ExclusionPath": exclusions}))

        return findings
