"""
WinSecure Windows Firewall Collector
"""
import json
from typing import Any, Dict
from winsecure.collectors.base import BaseCollector
from winsecure.utils.system import is_windows, run_powershell


class FirewallCollector(BaseCollector):
    name = "FirewallCollector"
    category = "Firewall"

    def _collect_internal(self) -> Dict[str, Any]:
        if not is_windows():
            return self.context.collected_artifacts.get("firewall", {})

        ps_script = """
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object -Property Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules, LogFileName, LogMaxSizeKilobytes, LogAllowed, LogBlocked
        $broad_rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | Where-Object {
            $portFilter = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $addrFilter = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
            ($addrFilter.RemoteAddress -eq 'Any' -or $addrFilter.RemoteAddress -eq '*') -and ($portFilter.LocalPort -match '^(3389|445|139|135|5985|5986|22|21|23)$')
        } | Select-Object -Property Name, DisplayName, Description, Profile -First 20

        @{
            Profiles = $profiles
            RiskyInboundRules = $broad_rules
        } | ConvertTo-Json -Depth 3
        """
        rc, stdout, stderr = run_powershell(ps_script, timeout=15)
        if rc == 0 and stdout:
            try:
                return json.loads(stdout)
            except Exception as e:
                return {"raw_output": stdout, "parse_error": str(e)}
        return {"error": stderr or "Firewall query failed"}
