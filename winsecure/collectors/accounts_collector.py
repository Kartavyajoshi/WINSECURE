"""
WinSecure Local Accounts & Privileges Collector
"""
import json
from typing import Any, Dict
from winsecure.collectors.base import BaseCollector
from winsecure.utils.system import is_windows, run_powershell, run_command


class AccountsCollector(BaseCollector):
    name = "AccountsCollector"
    category = "Accounts"

    def _collect_internal(self) -> Dict[str, Any]:
        if not is_windows():
            return self.context.collected_artifacts.get("accounts", {})

        ps_script = """
        $users = Get-LocalUser -ErrorAction SilentlyContinue | Select-Object -Property Name, Enabled, PasswordRequired, PasswordLastSet, LastLogon, UserMayChangePassword, PasswordExpires
        $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Select-Object -Property Name, PrincipalSource, ObjectClass
        $guests = Get-LocalGroupMember -Group 'Guests' -ErrorAction SilentlyContinue | Select-Object -Property Name, PrincipalSource, ObjectClass
        
        @{
            Users = $users
            Administrators = $admins
            Guests = $guests
        } | ConvertTo-Json -Depth 3
        """
        rc, stdout, stderr = run_powershell(ps_script, timeout=15)
        accounts_data = {}
        if rc == 0 and stdout:
            try:
                accounts_data = json.loads(stdout)
            except Exception:
                accounts_data["raw"] = stdout

        # Collect net accounts password policy
        rc_net, stdout_net, _ = run_command(["net", "accounts"], timeout=5)
        accounts_data["net_accounts_raw"] = stdout_net if rc_net == 0 else ""

        return accounts_data
