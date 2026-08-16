"""
WinSecure Audit Policy Collector
"""
import csv
import io
from typing import Any, Dict
from winsecure.collectors.base import BaseCollector
from winsecure.utils.system import is_windows, run_command


class AuditCollector(BaseCollector):
    name = "AuditCollector"
    category = "Audit"

    def _collect_internal(self) -> Dict[str, Any]:
        if not is_windows():
            return self.context.collected_artifacts.get("audit", {})

        rc, stdout, stderr = run_command(["auditpol.exe", "/get", "/category:*", "/r"], timeout=10)
        if rc == 0 and stdout:
            subcategories = {}
            try:
                reader = csv.reader(io.StringIO(stdout))
                for row in reader:
                    if len(row) >= 4 and row[0] != "Machine Name":
                        cat_name = row[1].strip()
                        subcat_name = row[2].strip()
                        setting = row[4].strip() if len(row) > 4 else row[3].strip()
                        subcategories[subcat_name] = {
                            "category": cat_name,
                            "setting": setting,
                        }
                return {"subcategories": subcategories}
            except Exception as e:
                return {"raw_csv": stdout, "parse_error": str(e)}
        return {"error": stderr or "auditpol command failed"}
