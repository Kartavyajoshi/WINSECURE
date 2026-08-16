"""
WinSecure Microsoft Defender Security Collector
"""
import json
from typing import Any, Dict
from winsecure.collectors.base import BaseCollector
from winsecure.utils.system import is_windows, run_powershell


class DefenderCollector(BaseCollector):
    name = "DefenderCollector"
    category = "Defender"

    def _collect_internal(self) -> Dict[str, Any]:
        if not is_windows():
            return self.context.collected_artifacts.get("defender", {})

        ps_script = """
        $status = Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object -Property @(
            'AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled',
            'IoavProtectionEnabled', 'OnAccessProtectionEnabled', 'ScriptScanningEnabled',
            'AntispywareEnabled', 'AntivirusSignatureAge', 'AntispywareSignatureAge',
            'AntivirusSignatureLastUpdated', 'NISSignatureAge', 'QuickScanAge',
            'FullScanAge', 'TamperProtectionSource', 'AMServiceEnabled',
            'IsTamperProtected', 'CloudProtectionLevel'
        )
        $pref = Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -Property @(
            'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableScriptScanning',
            'DisableIOAVProtection', 'DisablePrivacyMode', 'PUAProtection',
            'ControlledFolderAccessProtectedFolders', 'AttackSurfaceReductionRules_Ids',
            'AttackSurfaceReductionRules_Actions', 'ExclusionPath', 'ExclusionExtension',
            'ExclusionProcess', 'DisableArchiveScanning', 'SubmitSamplesConsent'
        )
        $out = @{
            Status = $status
            Preferences = $pref
        }
        $out | ConvertTo-Json -Depth 4
        """
        rc, stdout, stderr = run_powershell(ps_script, timeout=15)
        if rc == 0 and stdout:
            try:
                return json.loads(stdout)
            except Exception as e:
                return {"raw_output": stdout, "parse_error": str(e)}
        return {"error": stderr or "Defender cmdlets inaccessible (requires elevation)", "available": False}
