"""
WinSecure Plugin Framework
Base classes, hook contracts, and lifecycle events for third-party plugins.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from winsecure.version import __version__, __product_name__


class PluginHook:
    """Lifecycle hooks a plugin can implement (all optional except metadata)."""
    ON_INIT = "on_init"
    PRE_SCAN = "pre_scan"
    POST_FINDING = "post_finding"
    POST_SCAN = "post_scan"
    ON_REPORT = "on_report"


class WinSecurePlugin(ABC):
    """Abstract base class every WinSecure plugin must extend.

    Class attributes to override:
        plugin_id:    Unique identifier, e.g. "slack-notify".
        name:         Human-readable name.
        version:      Plugin semver string.
        author:       Author or organization.
        description:  Short purpose summary.
        hooks:        List of PluginHook constants this plugin implements.
    """

    plugin_id: str = "unnamed-plugin"
    name: str = "Unnamed Plugin"
    version: str = "0.1.0"
    author: str = "Unknown"
    description: str = ""
    homepage: str = ""
    hooks: List[str] = []

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config: Dict[str, Any] = config or {}
        self.enabled: bool = bool(self.config.get("enabled", True))

    # ------------------------------------------------------------------
    # Optional hook implementations (override as needed)
    # ------------------------------------------------------------------

    def on_init(self, context: Any) -> None:
        """Called once when the plugin is loaded, before any scan starts."""

    def pre_scan(self, context: Any) -> None:
        """Called immediately before the scan pipeline executes."""

    def post_finding(self, finding_dict: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """Called for each finding. May return a modified finding dict."""
        return finding_dict

    def post_scan(self, scan_result: Any) -> Any:
        """Called after the scan completes with the full ScanResult."""
        return scan_result

    def on_report(self, report_info: Dict[str, Any]) -> None:
        """Called after reports are generated.

        report_info contains:
            index_url:   file:// URL of the generated dashboard
            output_dir:  report directory path
            scan_id:     scan identifier
            score:       final security score
            risk_level:  risk level string
        """

    # ------------------------------------------------------------------
    # Metadata helpers
    # ------------------------------------------------------------------

    def get_report_url(self, report_info: Dict[str, Any]) -> str:
        """Convenience accessor for the generated dashboard URL."""
        return report_info.get("index_url", "")

    def metadata(self) -> Dict[str, Any]:
        """Returns plugin metadata for listing/registry purposes."""
        return {
            "plugin_id": self.plugin_id,
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "homepage": self.homepage,
            "hooks": list(self.hooks),
            "enabled": self.enabled,
            "host_compatible": __product_name__ + " " + __version__,
        }


class PluginError(Exception):
    """Raised when a plugin fails to load or execute."""
