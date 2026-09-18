"""
WinSecure Plugin Loader & Registry
Discovers, loads, validates, and dispatches lifecycle hooks to plugins.
"""
import importlib.util
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from winsecure.plugins.base import WinSecurePlugin, PluginError, PluginHook


class PluginRegistry:
    """Loads plugins from directories and dispatches hook events."""

    MANIFEST_NAME = "plugin.json"

    def __init__(self):
        self.plugins: Dict[str, WinSecurePlugin] = {}
        self.load_errors: List[Dict[str, str]] = []

    # ------------------------------------------------------------------
    # Discovery & loading
    # ------------------------------------------------------------------

    def discover(self, plugin_dirs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Scans directories for plugin packages and loads every valid one.

        A plugin is a folder containing:
            plugin.json   — manifest (name, entrypoint, config)
            <entry>.py    — python module with a class extending WinSecurePlugin
        """
        if not plugin_dirs:
            return []

        for plugin_dir in plugin_dirs:
            if not os.path.isdir(plugin_dir):
                continue
            for entry in sorted(Path(plugin_dir).iterdir()):
                if not entry.is_dir():
                    continue
                manifest_path = entry / self.MANIFEST_NAME
                if manifest_path.exists():
                    try:
                        self._load_from_manifest(entry, manifest_path)
                    except Exception as e:
                        self.load_errors.append({
                            "plugin": entry.name,
                            "error": f"{type(e).__name__}: {e}",
                        })
        return self.list_plugins()

    def _load_from_manifest(self, plugin_dir: Path, manifest_path: Path) -> None:
        """Loads one plugin from its manifest + entrypoint module."""
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)

        plugin_id = manifest.get("id")
        entry_file = manifest.get("entrypoint")
        class_name = manifest.get("class")

        if not all([plugin_id, entry_file, class_name]):
            raise PluginError("Manifest requires 'id', 'entrypoint', and 'class' fields")

        module_path = plugin_dir / entry_file
        if not module_path.exists():
            raise PluginError(f"Entrypoint not found: {entry_file}")

        # Internal module name must be a valid Python identifier
        module_name = "winsecure_plugin_" + re.sub(r"\W", "_", str(plugin_id))

        spec = importlib.util.spec_from_file_location(module_name, str(module_path))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        plugin_cls = getattr(module, class_name, None)
        if plugin_cls is None:
            raise PluginError(f"Class '{class_name}' not found in {entry_file}")
        if not (isinstance(plugin_cls, type) and issubclass(plugin_cls, WinSecurePlugin)):
            raise PluginError(f"'{class_name}' must extend WinSecurePlugin")

        instance = plugin_cls(config=manifest.get("config", {}))
        if instance.plugin_id != plugin_id:
            raise PluginError(
                f"Manifest id '{plugin_id}' does not match class plugin_id "
                f"'{instance.plugin_id}'"
            )
        self.register(instance)

    def register(self, plugin: WinSecurePlugin) -> None:
        """Registers a plugin instance by its plugin_id."""
        if plugin.plugin_id in self.plugins:
            raise PluginError(f"Duplicate plugin id: {plugin.plugin_id}")
        self.plugins[plugin.plugin_id] = plugin

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def list_plugins(self) -> List[Dict[str, Any]]:
        """Returns metadata for all loaded plugins."""
        return [p.metadata() for p in self.plugins.values()]

    def get(self, plugin_id: str) -> Optional[WinSecurePlugin]:
        """Fetches a loaded plugin by id."""
        return self.plugins.get(plugin_id)

    def has_hook_subscribers(self, hook: str) -> bool:
        """Returns True if at least one enabled plugin implements the hook."""
        return bool(self._enabled_with_hook(hook))

    # ------------------------------------------------------------------
    # Hook dispatch — a failing plugin never breaks the scan
    # ------------------------------------------------------------------

    def dispatch_init(self, context: Any) -> None:
        """Fires on_init for every enabled plugin."""
        for plugin in self._enabled_with_hook(PluginHook.ON_INIT):
            try:
                plugin.on_init(context)
            except Exception as e:
                self.load_errors.append({"plugin": plugin.plugin_id, "error": str(e)})

    def dispatch_pre_scan(self, context: Any) -> None:
        """Fires pre_scan for every enabled plugin."""
        for plugin in self._enabled_with_hook(PluginHook.PRE_SCAN):
            try:
                plugin.pre_scan(context)
            except Exception as e:
                self.load_errors.append({"plugin": plugin.plugin_id, "error": str(e)})

    def dispatch_post_finding(self, finding_dict: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """Passes the finding through each plugin's post_finding filter."""
        for plugin in self._enabled_with_hook(PluginHook.POST_FINDING):
            try:
                result = plugin.post_finding(finding_dict, context)
                if isinstance(result, dict):
                    finding_dict = result
            except Exception as e:
                self.load_errors.append({"plugin": plugin.plugin_id, "error": str(e)})
        return finding_dict

    def dispatch_post_scan(self, scan_result: Any) -> Any:
        """Passes the ScanResult through each plugin's post_scan."""
        for plugin in self._enabled_with_hook(PluginHook.POST_SCAN):
            try:
                out = plugin.post_scan(scan_result)
                if out is not None:
                    scan_result = out
            except Exception as e:
                self.load_errors.append({"plugin": plugin.plugin_id, "error": str(e)})
        return scan_result

    def dispatch_on_report(self, report_info: Dict[str, Any]) -> None:
        """Fires on_report with the dashboard URL and scan summary."""
        for plugin in self._enabled_with_hook(PluginHook.ON_REPORT):
            try:
                plugin.on_report(report_info)
            except Exception as e:
                self.load_errors.append({"plugin": plugin.plugin_id, "error": str(e)})

    def _enabled_with_hook(self, hook: str) -> List[WinSecurePlugin]:
        """Returns enabled plugins that implement the given hook."""
        return [
            p for p in self.plugins.values()
            if p.enabled and hook in p.hooks
        ]
