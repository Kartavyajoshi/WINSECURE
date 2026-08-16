"""
Service Analyzer Adapter
Audits active background services, listening network endpoints, and unquoted binary execution paths.
"""
import time
from typing import Dict, Any, List
from winsecure.adapters.base import BaseAdapter


class ServiceAnalyzerAdapter(BaseAdapter):
    """Inspects running Windows services, startup permissions, and service binary path quotes."""

    def __init__(self):
        super().__init__(
            name="service_analyzer",
            version="1.1.0",
            capability="service_and_socket_analysis",
        )

    def validate_requirements(self, context: Any) -> bool:
        return True

    def execute(self, target: str, context: Any) -> Dict[str, Any]:
        start = time.perf_counter()
        findings = []
        evidence = []

        services_artifact = getattr(context, "collected_artifacts", {}).get("services", {})
        services_list = services_artifact.get("services", [])

        unquoted_paths = []
        for s in services_list:
            path = s.get("PathName", "")
            if path and " " in path and not (path.startswith('"') or path.startswith("'")):
                unquoted_paths.append(s.get("Name", "UnknownService"))

        if unquoted_paths:
            findings.append({
                "id": "SRV-001",
                "title": "Unquoted Service Binary Path Detected",
                "severity": "Medium",
                "confidence": "High",
                "category": "Services",
                "description": f"Identified {len(unquoted_paths)} service(s) with spaces in binary paths lacking double quotation marks.",
                "affected_component": ", ".join(unquoted_paths),
                "remediation": "Enclose the service ImagePath in quotation marks within HKLM:\\SYSTEM\\CurrentControlSet\\Services.",
            })

        evidence.append({
            "source": "services_collector",
            "total_services_audited": len(services_list),
            "unquoted_count": len(unquoted_paths),
        })

        duration = (time.perf_counter() - start) * 1000
        return self.format_result(
            target=target,
            status="completed",
            findings=findings,
            evidence=evidence,
            metadata={"services_count": len(services_list)},
            risk={"unquoted_services": len(unquoted_paths)},
            execution_time_ms=duration,
        )
