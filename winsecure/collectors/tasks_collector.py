"""
WinSecure Scheduled Tasks Collector
"""
import csv
import io
from typing import Any, Dict, List
from winsecure.collectors.base import BaseCollector
from winsecure.utils.system import is_windows, run_command


class TasksCollector(BaseCollector):
    name = "TasksCollector"
    category = "Tasks"

    def _collect_internal(self) -> Dict[str, Any]:
        if not is_windows():
            return self.context.collected_artifacts.get("tasks", {})

        rc, stdout, stderr = run_command(["schtasks.exe", "/query", "/fo", "csv", "/v"], timeout=20)
        tasks = []
        if rc == 0 and stdout:
            try:
                reader = csv.DictReader(io.StringIO(stdout))
                for row in reader:
                    task_name = row.get("TaskName", "")
                    action = row.get("Task To Run", "")
                    run_as = row.get("Run As User", "")
                    status = row.get("Status", "")
                    tasks.append({
                        "name": task_name,
                        "action": action,
                        "run_as": run_as,
                        "status": status,
                    })
                return {"tasks": tasks[:100]}
            except Exception as e:
                return {"raw": stdout[:1000], "parse_error": str(e)}
        return {"tasks": [], "error": stderr or "schtasks query failed"}
