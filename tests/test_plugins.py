"""
Unit Tests for the WinSecure Plugin Framework
"""
import json
import os
import tempfile
import unittest

from winsecure.plugins.base import WinSecurePlugin, PluginError, PluginHook
from winsecure.plugins.loader import PluginRegistry


class DummyPlugin(WinSecurePlugin):
    plugin_id = "dummy"
    name = "Dummy"
    version = "1.0.0"
    author = "Test"
    description = "Test plugin"
    hooks = [PluginHook.ON_INIT, PluginHook.POST_FINDING, PluginHook.ON_REPORT]

    def __init__(self, config=None):
        super().__init__(config)
        self.init_called = False
        self.report_info = None

    def on_init(self, context):
        self.init_called = True

    def post_finding(self, finding_dict, context):
        finding_dict = dict(finding_dict)
        finding_dict["metadata"]["touched_by"] = self.plugin_id
        return finding_dict

    def on_report(self, report_info):
        self.report_info = report_info


class TestPluginBase(unittest.TestCase):
    def test_metadata_shape(self):
        p = DummyPlugin()
        meta = p.metadata()
        for key in ("plugin_id", "name", "version", "author", "hooks", "enabled"):
            self.assertIn(key, meta)
        self.assertEqual(meta["plugin_id"], "dummy")

    def test_report_url_accessor(self):
        p = DummyPlugin()
        url = p.get_report_url({"index_url": "file:///report/index.html"})
        self.assertEqual(url, "file:///report/index.html")
        self.assertEqual(p.get_report_url({}), "")


class TestRegistry(unittest.TestCase):
    def test_register_and_list(self):
        reg = PluginRegistry()
        reg.register(DummyPlugin())
        listing = reg.list_plugins()
        self.assertEqual(len(listing), 1)
        self.assertEqual(listing[0]["plugin_id"], "dummy")

    def test_duplicate_registration_rejected(self):
        reg = PluginRegistry()
        reg.register(DummyPlugin())
        with self.assertRaises(PluginError):
            reg.register(DummyPlugin())

    def test_disabled_plugin_skips_hooks(self):
        reg = PluginRegistry()
        plugin = DummyPlugin(config={"enabled": False})
        reg.register(plugin)
        reg.dispatch_init(None)
        self.assertFalse(plugin.init_called)

    def test_post_finding_chain(self):
        reg = PluginRegistry()
        reg.register(DummyPlugin())
        out = reg.dispatch_post_finding({"id": "WS-X-001", "metadata": {}}, None)
        self.assertEqual(out["metadata"]["touched_by"], "dummy")

    def test_on_report_receives_url(self):
        reg = PluginRegistry()
        plugin = DummyPlugin()
        reg.register(plugin)
        info = {"index_url": "file:///r/index.html", "scan_id": "SCAN-1"}
        reg.dispatch_on_report(info)
        self.assertEqual(plugin.report_info["index_url"], "file:///r/index.html")

    def test_failing_hook_does_not_raise(self):
        class Bad(WinSecurePlugin):
            plugin_id = "bad"
            hooks = [PluginHook.ON_INIT]
            def on_init(self, context):
                raise RuntimeError("boom")

        reg = PluginRegistry()
        reg.register(Bad())
        reg.dispatch_init(None)  # must not raise
        self.assertTrue(any(e["plugin"] == "bad" for e in reg.load_errors))


class TestDiscoveryFromDisk(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # Build a plugin package on disk: manifest + module
        pkg = os.path.join(self.tmp.name, "my-plugin")
        os.makedirs(pkg)
        with open(os.path.join(pkg, "plugin.json"), "w", encoding="utf-8") as fh:
            json.dump({
                "id": "disk-plugin",
                "name": "Disk Plugin",
                "version": "0.2.0",
                "entrypoint": "impl.py",
                "class": "DiskPlugin",
                "config": {"enabled": True},
            }, fh)
        with open(os.path.join(pkg, "impl.py"), "w", encoding="utf-8") as fh:
            fh.write(
                "from winsecure.plugins.base import WinSecurePlugin\n"
                "class DiskPlugin(WinSecurePlugin):\n"
                "    plugin_id = 'disk-plugin'\n"
                "    hooks = ['on_init']\n"
            )

    def tearDown(self):
        self.tmp.cleanup()

    def test_discover_loads_disk_plugin(self):
        reg = PluginRegistry()
        listing = reg.discover([self.tmp.name])
        ids = [p["plugin_id"] for p in listing]
        self.assertIn("disk-plugin", ids)

    def test_discover_missing_dir_is_noop(self):
        reg = PluginRegistry()
        listing = reg.discover(["Z:/definitely/not/real"])
        self.assertEqual(listing, [])

    def test_broken_manifest_recorded_as_error(self):
        pkg = os.path.join(self.tmp.name, "broken")
        os.makedirs(pkg, exist_ok=True)
        with open(os.path.join(pkg, "plugin.json"), "w", encoding="utf-8") as fh:
            fh.write("{ not valid json")
        reg = PluginRegistry()
        reg.discover([self.tmp.name])
        self.assertTrue(any(e["plugin"] == "broken" for e in reg.load_errors))

    def test_manifest_id_mismatch_rejected(self):
        pkg = os.path.join(self.tmp.name, "mismatched")
        os.makedirs(pkg, exist_ok=True)
        with open(os.path.join(pkg, "plugin.json"), "w", encoding="utf-8") as fh:
            json.dump({
                "id": "wrong-id",
                "entrypoint": "impl.py",
                "class": "MismatchPlugin",
            }, fh)
        with open(os.path.join(pkg, "impl.py"), "w", encoding="utf-8") as fh:
            fh.write(
                "from winsecure.plugins.base import WinSecurePlugin\n"
                "class MismatchPlugin(WinSecurePlugin):\n"
                "    plugin_id = 'actual-id'\n"
            )
        reg = PluginRegistry()
        reg.discover([self.tmp.name])
        self.assertNotIn("actual-id", reg.plugins)
        self.assertTrue(any(e["plugin"] == "mismatched" for e in reg.load_errors))

    def test_has_hook_subscribers(self):
        reg = PluginRegistry()
        reg.register(DummyPlugin())  # implements POST_FINDING
        self.assertTrue(reg.has_hook_subscribers(PluginHook.POST_FINDING))
        self.assertFalse(reg.has_hook_subscribers(PluginHook.PRE_SCAN))


if __name__ == "__main__":
    unittest.main()
