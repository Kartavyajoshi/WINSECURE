"""
WinSecure PowerShell Data Collector
"""
import json
from typing import Any, Dict, Optional
from winsecure.collectors.base import BaseCollector
from winsecure.utils.system import is_windows, run_powershell


class PowerShellCollector(BaseCollector):
    name = "PowerShellCollector"
    category = "PowerShell"

    def _collect_internal(self) -> Dict[str, Any]:
        if not is_windows():
            return self.context.collected_artifacts.get("powershell", {})

        # Execute safe querying PowerShell blocks
        scripts = {
            "execution_policy": "$res = @{ MachinePolicy = (Get-ExecutionPolicy -Scope MachinePolicy).ToString(); UserPolicy = (Get-ExecutionPolicy -Scope UserPolicy).ToString(); Process = (Get-ExecutionPolicy -Scope Process).ToString(); CurrentUser = (Get-ExecutionPolicy -Scope CurrentUser).ToString(); LocalMachine = (Get-ExecutionPolicy -Scope LocalMachine).ToString() }; $res | ConvertTo-Json",
            "ps_version": "$PSVersionTable | ConvertTo-Json",
            "clm_state": "$ExecutionContext.SessionState.LanguageMode.ToString()",
        }

        results = {}
        for key, script in scripts.items():
            rc, stdout, stderr = run_powershell(script, timeout=10)
            if rc == 0 and stdout:
                try:
                    results[key] = json.loads(stdout)
                except Exception:
                    results[key] = stdout.strip()
            else:
                results[key] = {"error": stderr or "Failed to query"}

        return results
