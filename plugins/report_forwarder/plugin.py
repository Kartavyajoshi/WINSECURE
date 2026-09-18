"""
WinSecure Sample Plugin — Report URL Forwarder
Demonstrates the plugin lifecycle: receives the generated report dashboard
URL after every scan and forwards it (with scan summary) to an HTTP endpoint.
"""
import json
from typing import Any, Dict

from winsecure.plugins.base import WinSecurePlugin, PluginHook


class ReportForwarderPlugin(WinSecurePlugin):
    """Sends the report URL + scan summary to a configured endpoint."""

    plugin_id = "report-forwarder"
    name = "Report URL Forwarder"
    version = "1.0.0"
    author = "WinSecure Team"
    description = "Forwards the generated report dashboard URL and scan summary to any HTTP endpoint."
    homepage = "https://github.com/Kartavyajoshi/WINSECURE"
    hooks = [PluginHook.ON_INIT, PluginHook.ON_REPORT]

    def on_init(self, context: Any) -> None:
        """Validates configuration at load time."""
        self.endpoint_url = self.config.get("endpoint_url", "")
        self.extra_headers: Dict[str, str] = self.config.get("extra_headers", {}) or {}
        if not self.endpoint_url:
            # Disabled-but-loaded: registry will simply skip delivery.
            self.enabled = False

    def on_report(self, report_info: Dict[str, Any]) -> None:
        """POSTs the report URL and scan summary to the configured endpoint."""
        payload = {
            "event": "report.generated",
            "report_url": self.get_report_url(report_info),
            "scan_id": report_info.get("scan_id"),
            "security_score": report_info.get("score"),
            "risk_level": report_info.get("risk_level"),
            "output_dir": report_info.get("output_dir"),
        }
        self._deliver(payload)

    def _deliver(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Performs the HTTP POST; returns a delivery result dict."""
        from urllib import request as urllib_request

        body = json.dumps(payload, default=str).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        headers.update(self.extra_headers)

        req = urllib_request.Request(
            self.endpoint_url, data=body, headers=headers, method="POST"
        )
        try:
            with urllib_request.urlopen(req, timeout=5) as resp:
                return {"delivered": True, "status": resp.status}
        except Exception as e:
            return {"delivered": False, "error": str(e)}
