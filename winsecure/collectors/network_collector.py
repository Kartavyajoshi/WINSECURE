"""
WinSecure Network Configuration & Exposure Collector
"""
import json
from typing import Any, Dict
from winsecure.collectors.base import BaseCollector
from winsecure.utils.system import is_windows, run_powershell


class NetworkCollector(BaseCollector):
    name = "NetworkCollector"
    category = "Network"

    def _collect_internal(self) -> Dict[str, Any]:
        if not is_windows():
            return self.context.collected_artifacts.get("network", {})

        ps_script = """
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -Property LocalAddress, LocalPort, OwningProcess -First 50
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object -Property Name, InterfaceDescription, Status, MacAddress, LinkSpeed
        @{
            Listeners = $listeners
            Adapters = $adapters
        } | ConvertTo-Json -Depth 3
        """
        rc, stdout, stderr = run_powershell(ps_script, timeout=15)
        if rc == 0 and stdout:
            try:
                return json.loads(stdout)
            except Exception:
                pass
        return {"error": stderr or "Failed to query NetTCPConnection"}
