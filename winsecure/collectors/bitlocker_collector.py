"""
WinSecure BitLocker & Device Encryption Collector
"""
import json
from typing import Any, Dict
from winsecure.collectors.base import BaseCollector
from winsecure.utils.system import is_windows, run_powershell


class BitLockerCollector(BaseCollector):
    name = "BitLockerCollector"
    category = "Encryption"

    def _collect_internal(self) -> Dict[str, Any]:
        if not is_windows():
            return self.context.collected_artifacts.get("bitlocker", {})

        ps_script = """
        Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object -Property @(
            'MountPoint', 'VolumeType', 'VolumeStatus', 'ProtectionStatus',
            'EncryptionPercentage', 'EncryptionMethod', 'AutoUnlockEnabled'
        ) | ConvertTo-Json -Depth 2
        """
        rc, stdout, stderr = run_powershell(ps_script, timeout=15)
        if rc == 0 and stdout:
            try:
                data = json.loads(stdout)
                if isinstance(data, dict):
                    data = [data]
                return {"volumes": data}
            except Exception as e:
                return {"raw": stdout, "parse_error": str(e)}
        return {"volumes": [], "error": stderr or "BitLocker cmdlets inaccessible"}
