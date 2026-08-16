"""
WinSecure Services Collector
"""
import json
from typing import Any, Dict, List
from winsecure.collectors.base import BaseCollector
from winsecure.utils.system import is_windows, run_powershell


class ServicesCollector(BaseCollector):
    name = "ServicesCollector"
    category = "Services"

    def _collect_internal(self) -> Dict[str, Any]:
        if not is_windows():
            return self.context.collected_artifacts.get("services", {})

        ps_script = """
        Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue | Select-Object -Property Name, DisplayName, State, StartMode, StartName, PathName | ConvertTo-Json -Depth 2
        """
        rc, stdout, stderr = run_powershell(ps_script, timeout=20)
        if rc == 0 and stdout:
            try:
                data = json.loads(stdout)
                if isinstance(data, dict):
                    data = [data]
                return {"services": data}
            except Exception as e:
                return {"raw_services": stdout, "error": str(e)}
        return {"services": [], "error": stderr or "Failed to query Win32_Service"}
