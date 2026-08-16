"""
WinSecure Installed Software Inventory Collector
"""
from typing import Any, Dict, List
from winsecure.collectors.base import BaseCollector
from winsecure.utils.system import is_windows


class SoftwareCollector(BaseCollector):
    name = "SoftwareCollector"
    category = "Software"

    def _collect_internal(self) -> Dict[str, Any]:
        if not is_windows():
            return self.context.collected_artifacts.get("software", {})

        import winreg
        installed = []
        paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", True),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", False),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", True),
        ]

        for hive, subkey, is_64 in paths:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                    num_subkeys = winreg.QueryInfoKey(key)[0]
                    for i in range(num_subkeys):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as app_key:
                                try:
                                    display_name = winreg.QueryValueEx(app_key, "DisplayName")[0]
                                    version = winreg.QueryValueEx(app_key, "DisplayVersion")[0] if "DisplayVersion" in [winreg.EnumValue(app_key, j)[0] for j in range(winreg.QueryInfoKey(app_key)[1])] else "Unknown"
                                    publisher = winreg.QueryValueEx(app_key, "Publisher")[0] if "Publisher" in [winreg.EnumValue(app_key, j)[0] for j in range(winreg.QueryInfoKey(app_key)[1])] else "Unknown"
                                    install_loc = winreg.QueryValueEx(app_key, "InstallLocation")[0] if "InstallLocation" in [winreg.EnumValue(app_key, j)[0] for j in range(winreg.QueryInfoKey(app_key)[1])] else ""
                                    installed.append({
                                        "name": display_name,
                                        "version": version,
                                        "vendor": publisher,
                                        "location": install_loc,
                                        "is_64bit": is_64,
                                    })
                                except Exception:
                                    continue
                        except Exception:
                            continue
            except Exception:
                continue

        return {"installed_software": installed}
