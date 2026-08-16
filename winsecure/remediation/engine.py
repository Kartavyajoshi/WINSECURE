"""
WinSecure Remediation Engine & Guidance Generator
"""
from typing import Dict, List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.remediation import RemediationAction, RemediationPriority


class RemediationEngine:
    """Generates actionable, verified remediation steps and scripts for failing findings."""

    # Built-in tailored scripts per finding ID
    SCRIPTS_MAP = {
        "WS-DEF-001": {
            "ps": "Set-MpPreference -DisableRealtimeMonitoring $false",
            "gpo": "Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Real-time Protection > Turn off real-time protection = Disabled",
            "rollback": "Set-MpPreference -DisableRealtimeMonitoring $true",
            "validation": "(Get-MpComputerStatus).RealTimeProtectionEnabled",
            "effort": 2,
            "reboot": False,
        },
        "WS-DEF-002": {
            "ps": "Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendAllSamples",
            "gpo": "Windows Components > Microsoft Defender Antivirus > MAPS > Join Microsoft MAPS = Enabled",
            "rollback": "Set-MpPreference -MAPSReporting Disabled",
            "validation": "(Get-MpComputerStatus).CloudProtectionLevel",
            "effort": 2,
            "reboot": False,
        },
        "WS-FW-001": {
            "ps": "Set-NetFirewallProfile -Profile Public -Enabled True -DefaultInboundAction Block",
            "gpo": "Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Public Profile = On",
            "rollback": "Set-NetFirewallProfile -Profile Public -Enabled False",
            "validation": "(Get-NetFirewallProfile -Profile Public).Enabled",
            "effort": 2,
            "reboot": False,
        },
        "WS-ACC-001": {
            "ps": "Disable-LocalUser -Name 'Guest'",
            "gpo": "Security Settings > Local Policies > Security Options > Accounts: Guest account status = Disabled",
            "rollback": "Enable-LocalUser -Name 'Guest'",
            "validation": "(Get-LocalUser -Name 'Guest').Enabled",
            "effort": 1,
            "reboot": False,
        },
        "WS-ACC-003": {
            "ps": "net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15",
            "gpo": "Security Settings > Account Policies > Account Lockout Policy > Account lockout threshold = 5",
            "rollback": "net accounts /lockoutthreshold:0",
            "validation": "net accounts",
            "effort": 3,
            "reboot": False,
        },
        "WS-UAC-001": {
            "ps": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1",
            "gpo": "Security Settings > Local Policies > Security Options > User Account Control: Run all administrators in Admin Approval Mode = Enabled",
            "rollback": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 0",
            "validation": "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA'",
            "effort": 5,
            "reboot": True,
        },
        "WS-SMB-001": {
            "ps": "Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart; Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
            "gpo": "Administrative Templates > Network > Lanman Workstation > Enable insecure guest logons = Disabled",
            "rollback": "Enable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart",
            "validation": "(Get-SmbServerConfiguration).EnableSMB1Protocol",
            "effort": 5,
            "reboot": True,
        },
        "WS-REG-001": {
            "ps": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1",
            "gpo": "Administrative Templates > System > Local Security Authority > Configures LSASS to run as a protected process = Enabled",
            "rollback": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 0",
            "validation": "Get-ItemPropertyValue 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL'",
            "effort": 3,
            "reboot": True,
        },
        "WS-PS-001": {
            "ps": "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1",
            "gpo": "Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging = Enabled",
            "rollback": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 0",
            "validation": "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging'",
            "effort": 2,
            "reboot": False,
        },
        "WS-AUD-001": {
            "ps": "auditpol.exe /set /subcategory:'Process Creation' /success:enable /failure:enable",
            "gpo": "Security Settings > Advanced Audit Policy Configuration > Detailed Tracking > Audit Process Creation = Success and Failure",
            "rollback": "auditpol.exe /set /subcategory:'Process Creation' /success:disable /failure:disable",
            "validation": "auditpol.exe /get /subcategory:'Process Creation'",
            "effort": 2,
            "reboot": False,
        },
        "WS-RDP-001": {
            "ps": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1",
            "gpo": "Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > Require user authentication for remote connections by using Network Level Authentication = Enabled",
            "rollback": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 0",
            "validation": "Get-ItemPropertyValue 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication'",
            "effort": 2,
            "reboot": False,
        },
    }

    @classmethod
    def generate_remediations(cls, findings: List[Finding]) -> List[RemediationAction]:
        remediations = []
        for f in findings:
            if f.status in [FindingStatus.FAIL, FindingStatus.WARN]:
                template = cls.SCRIPTS_MAP.get(f.id, {})
                priority = RemediationPriority.from_severity(f.severity.value)

                action = RemediationAction(
                    finding_id=f.id,
                    title=f.title,
                    category=f.category,
                    priority=priority,
                    what_is_wrong=f"Observed: {f.actual}. Expected: {f.expected}.",
                    why_it_matters=f.impact or "Reduces endpoint attack surface and ensures policy compliance.",
                    how_to_fix=f.remediation or "Apply recommended security policy or registry setting.",
                    powershell_script=template.get("ps", f"# Remediation for {f.id}\nWrite-Output 'Apply configuration: {f.remediation}'"),
                    gpo_or_gui_alternative=template.get("gpo"),
                    side_effects="Standard security hardening setting; verify compatibility in specialized legacy environments.",
                    rollback_guidance=template.get("rollback", "Revert modified registry keys or group policy to previous state."),
                    validation_command=template.get("validation", "# Run scan again to verify: winsecure scan"),
                    estimated_effort_minutes=template.get("effort", 5),
                    requires_reboot=template.get("reboot", False),
                )
                remediations.append(action)

        # Sort by priority
        p_order = {
            RemediationPriority.P0_IMMEDIATE: 0,
            RemediationPriority.P1_HIGH: 1,
            RemediationPriority.P2_MEDIUM: 2,
            RemediationPriority.P3_LOW: 3,
            RemediationPriority.P4_LONG_TERM: 4,
        }
        remediations.sort(key=lambda r: p_order.get(r.priority, 5))
        return remediations
