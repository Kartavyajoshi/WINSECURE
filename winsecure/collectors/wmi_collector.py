"""
WinSecure WMI / CIM Hardware and System Collector
"""
import json
from typing import Any, Dict
from winsecure.collectors.base import BaseCollector
from winsecure.utils.system import is_windows, run_powershell


class WmiCollector(BaseCollector):
    name = "WmiCollector"
    category = "System"

    def _collect_internal(self) -> Dict[str, Any]:
        if not is_windows():
            return self.context.collected_artifacts.get("wmi", {})

        ps_script = """
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -Property Caption, Version, BuildNumber, OSArchitecture, TotalVisibleMemorySize, FreePhysicalMemory, LastBootUpTime
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -Property Name, Domain, Manufacturer, Model, TotalPhysicalMemory
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -Property SMBIOSBIOSVersion, ReleaseDate, Manufacturer
        $proc = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -Property Name, NumberOfCores, NumberOfLogicalProcessors -First 1
        
        @{
            OperatingSystem = $os
            ComputerSystem = $cs
            BIOS = $bios
            Processor = $proc
        } | ConvertTo-Json -Depth 3
        """
        rc, stdout, stderr = run_powershell(ps_script, timeout=15)
        if rc == 0 and stdout:
            try:
                return json.loads(stdout)
            except Exception:
                pass
        return {"error": stderr or "Failed to query CIM instances"}
