"""
WinSecure Windows Update Collector
"""
import json
from typing import Any, Dict
from winsecure.collectors.base import BaseCollector
from winsecure.utils.system import is_windows, run_powershell


class UpdatesCollector(BaseCollector):
    name = "UpdatesCollector"
    category = "Updates"

    def _collect_internal(self) -> Dict[str, Any]:
        if not is_windows():
            return self.context.collected_artifacts.get("updates", {})

        ps_script = """
        $session = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
        $searcher = $session.CreateUpdateSearcher()
        $pending_reboot = (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') -or (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired')
        $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Select-Object -Property HotFixID, InstalledOn, Description -Last 10
        @{
            PendingReboot = $pending_reboot
            RecentHotfixes = $hotfixes
        } | ConvertTo-Json -Depth 3
        """
        rc, stdout, stderr = run_powershell(ps_script, timeout=15)
        if rc == 0 and stdout:
            try:
                return json.loads(stdout)
            except Exception:
                pass
        return {"PendingReboot": False, "RecentHotfixes": []}
