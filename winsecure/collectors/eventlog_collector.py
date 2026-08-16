"""
WinSecure Windows Event Logs Collector
"""
import json
from typing import Any, Dict
from winsecure.collectors.base import BaseCollector
from winsecure.utils.system import is_windows, run_powershell


class EventLogCollector(BaseCollector):
    name = "EventLogCollector"
    category = "EventLogs"

    def _collect_internal(self) -> Dict[str, Any]:
        if not is_windows():
            return self.context.collected_artifacts.get("eventlogs", {})

        ps_script = """
        $sec = Get-WinEvent -ListLog 'Security' -ErrorAction SilentlyContinue | Select-Object -Property LogName, IsEnabled, MaximumSizeInBytes, LogMode
        $sys = Get-WinEvent -ListLog 'System' -ErrorAction SilentlyContinue | Select-Object -Property LogName, IsEnabled, MaximumSizeInBytes, LogMode
        $ps = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' -ErrorAction SilentlyContinue | Select-Object -Property LogName, IsEnabled, MaximumSizeInBytes, LogMode
        @{
            Security = $sec
            System = $sys
            PowerShellOperational = $ps
        } | ConvertTo-Json -Depth 2
        """
        rc, stdout, stderr = run_powershell(ps_script, timeout=15)
        if rc == 0 and stdout:
            try:
                return json.loads(stdout)
            except Exception:
                pass
        return {"error": stderr or "Failed to query WinEvent channels"}
