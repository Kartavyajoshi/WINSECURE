"""
WinSecure Safe Read-Only Registry Collector
"""
from typing import Any, Dict, Optional
from winsecure.collectors.base import BaseCollector
from winsecure.utils.system import is_windows

# Root hive mappings
HIVE_NAMES = {
    "HKLM": 0x80000002,  # HKEY_LOCAL_MACHINE
    "HKCU": 0x80000001,  # HKEY_CURRENT_USER
    "HKCR": 0x80000000,  # HKEY_CLASSES_ROOT
    "HKU":  0x80000003,  # HKEY_USERS
}


class RegistryCollector(BaseCollector):
    name = "RegistryCollector"
    category = "Registry"

    def _collect_internal(self) -> Dict[str, Any]:
        if not is_windows():
            # If running on simulated/non-Windows context, check fixture artifacts
            return self.context.collected_artifacts.get("registry", {})
        
        # Real Windows registry collection
        import winreg
        results = {}
        target_keys = [
            ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", ["ProductName", "CurrentBuild", "DisplayVersion"]),
            ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender", ["DisableAntiSpyware", "DisableRealtimeMonitoring"]),
            ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", ["DisableBehaviorMonitoring", "DisableOnAccessProtection", "DisableScanOnRealtimeEnable", "DisableIOAVProtection"]),
            ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", ["EnableSmartScreen", "PublishUserActivities"]),
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", ["EnableLUA", "ConsentPromptBehaviorAdmin", "ConsentPromptBehaviorUser", "PromptOnSecureDesktop", "FilterAdministratorToken"]),
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", ["RunAsPPL", "LsaCfgFlags", "LmCompatibilityLevel", "NoLMHash", "RestrictAnonymous", "RestrictAnonymousSAM", "LimitBlankPasswordUse", "AuditBaseObjects"]),
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", ["UseLogonCredential"]),
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager", ["ProtectionMode", "SafeDllSearchMode"]),
            ("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", ["SMB1", "RequireSecuritySignature", "EnableSecuritySignature", "AutoDisconnect", "NullSessionPipes", "NullSessionShares"]),
            ("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", ["RequireSecuritySignature", "EnableSecuritySignature", "AllowInsecureGuestAuth"]),
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", ["fDenyTSConnections", "fPromptForPassword"]),
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", ["UserAuthentication", "SecurityLayer", "MinEncryptionLevel"]),
            ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", ["EnableScriptBlockLogging", "EnableScriptBlockInvocationLogging"]),
            ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", ["EnableModuleLogging"]),
            ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", ["EnableTranscripting"]),
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", ["FeatureSettingsOverride", "FeatureSettingsOverrideMask"]),
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", []),
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", []),
            ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", []),
            ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", []),
        ]

        hives = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
            "HKU": winreg.HKEY_USERS,
        }

        for hive_name, subkey, val_names in target_keys:
            full_path = f"{hive_name}\\{subkey}"
            hive_val = hives.get(hive_name)
            if not hive_val:
                continue
            try:
                with winreg.OpenKey(hive_val, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    values_dict = {}
                    if not val_names:
                        # Enumerate all values
                        try:
                            i = 0
                            while True:
                                name, val, v_type = winreg.EnumValue(key, i)
                                values_dict[name] = val
                                i += 1
                        except OSError:
                            pass
                    else:
                        for vn in val_names:
                            try:
                                val, v_type = winreg.QueryValueEx(key, vn)
                                values_dict[vn] = val
                            except FileNotFoundError:
                                values_dict[vn] = None
                    results[full_path] = values_dict
            except FileNotFoundError:
                results[full_path] = {"_exists": False}
            except Exception as e:
                results[full_path] = {"_error": str(e)}

        return results

    def get_value(self, hive: str, subkey: str, value_name: str) -> Optional[Any]:
        """Convenience method to look up a cached or collected registry value."""
        if not self._cache:
            self._cache = self.collect()
        full_path = f"{hive}\\{subkey}"
        key_data = self._cache.get(full_path, {})
        return key_data.get(value_name)
