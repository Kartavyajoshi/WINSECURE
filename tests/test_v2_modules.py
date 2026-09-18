"""
Unit Tests for v2 Modules: Drift/Trend, Script Generator, SIEM Export, API Server
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from winsecure.models import ScanResult, Finding, Severity, FindingStatus, RiskLevel
from winsecure.analytics.drift_trend import DriftTrendEngine, TrendDirection
from winsecure.remediation.script_generator import RemediationScriptGenerator
from winsecure.reporting.siem_exporter import SiemExporter
from winsecure.cli.parser import create_cli_parser


def _make_finding(fid="WS-DEF-001", status=FindingStatus.FAIL,
                  severity=Severity.CRITICAL, category="Defender"):
    return Finding(
        id=fid,
        title=f"Test finding {fid}",
        category=category,
        severity=severity,
        status=status,
        confidence=0.95,
        description="Test description",
        expected="Secure value",
        actual="Insecure value",
        impact="Test impact",
        remediation="Enable the secure setting",
    )


def _make_scan(scan_id="SCAN-TEST001", score=75.0, findings=None):
    return ScanResult(
        scan_id=scan_id,
        timestamp="2026-08-20T12:00:00Z",
        winsecure_version="2.0.0",
        profile="standard",
        is_admin=True,
        security_score=score,
        risk_level=RiskLevel.from_score(score),
        findings=findings if findings is not None else [_make_finding()],
    )


class TestDriftTrendEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "trend.db")
        from winsecure.storage import DatabaseManager, ScanRepository
        self.db_mgr = DatabaseManager(self.db_path)
        self.repo = ScanRepository(self.db_mgr)

    def tearDown(self):
        self.db_mgr.close()
        self.temp_dir.cleanup()

    def _seed_history(self, scores):
        for i, score in enumerate(scores):
            scan = _make_scan(scan_id=f"SCAN-T{i:03d}", score=score)
            scan.timestamp = f"2026-08-{10 + i:02d}T12:00:00Z"
            self.repo.save_scan_result(scan)

    def test_insufficient_history(self):
        engine = DriftTrendEngine(self.db_path)
        try:
            report = engine.analyze_trend()
            self.assertFalse(report["has_history"])
            self.assertEqual(report["direction"], TrendDirection.INSUFFICIENT_DATA)
        finally:
            engine.close()

    def test_declining_trend_detected(self):
        self._seed_history([90.0, 80.0, 70.0])
        engine = DriftTrendEngine(self.db_path)
        try:
            report = engine.analyze_trend()
            self.assertTrue(report["has_history"])
            self.assertEqual(report["direction"], TrendDirection.DECLINING)
            self.assertEqual(report["net_change"], -20.0)
            self.assertEqual(report["declining_steps"], 2)
        finally:
            engine.close()

    def test_improving_trend_detected(self):
        self._seed_history([60.0, 70.0, 85.0])
        engine = DriftTrendEngine(self.db_path)
        try:
            report = engine.analyze_trend()
            self.assertEqual(report["direction"], TrendDirection.IMPROVING)
            self.assertEqual(report["net_change"], 25.0)
        finally:
            engine.close()

    def test_recurring_failures_found(self):
        # Same failing finding across 3 scans
        self._seed_history([90.0, 85.0, 80.0])
        engine = DriftTrendEngine(self.db_path)
        try:
            recurring = engine.find_recurring_failures(min_occurrences=2)
            self.assertTrue(len(recurring) >= 1)
            target = next(
                (e for e in recurring if e["finding_id"] == "WS-DEF-001"), None
            )
            self.assertIsNotNone(target)
            self.assertGreaterEqual(target["occurrences"], 3)
        finally:
            engine.close()

    def test_full_report_contains_both_sections(self):
        self._seed_history([90.0, 80.0, 70.0])
        engine = DriftTrendEngine(self.db_path)
        try:
            report = engine.build_full_report()
            self.assertIn("direction", report)
            self.assertIn("recurring_failures", report)
        finally:
            engine.close()


class TestRemediationScriptGenerator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generates_script_bundle(self):
        scan = _make_scan(findings=[_make_finding()])
        gen = RemediationScriptGenerator(self.temp_dir.name)
        info = gen.generate_bundle(scan)

        self.assertEqual(info["script_count"], 1)
        scripts_dir = info["scripts_directory"]
        self.assertTrue(os.path.isdir(scripts_dir))
        self.assertTrue(os.path.exists(info["run_all_script"]))
        self.assertTrue(os.path.exists(os.path.join(scripts_dir, "WS-DEF-001_fix.ps1")))
        self.assertTrue(os.path.exists(os.path.join(scripts_dir, "WS-DEF-001_rollback.ps1")))
        self.assertTrue(os.path.exists(os.path.join(scripts_dir, "WS-DEF-001_validate.ps1")))

    def test_run_all_references_fix_scripts(self):
        scan = _make_scan(findings=[_make_finding(), _make_finding("WS-FW-001")])
        gen = RemediationScriptGenerator(self.temp_dir.name)
        info = gen.generate_bundle(scan)

        with open(info["run_all_script"], encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("WS-DEF-001_fix.ps1", content)
        self.assertIn("WS-FW-001_fix.ps1", content)

    def test_no_actions_produces_empty_manifest(self):
        scan = _make_scan(findings=[_make_finding(status=FindingStatus.PASS)])
        gen = RemediationScriptGenerator(self.temp_dir.name)
        info = gen.generate_bundle(scan)
        self.assertEqual(info["script_count"], 0)

    def test_unsafe_filename_chars_sanitized(self):
        scan = _make_scan(findings=[_make_finding(fid="WS:BAD*NAME?")])
        gen = RemediationScriptGenerator(self.temp_dir.name)
        info = gen.generate_bundle(scan)
        expected_fix = os.path.join(
            info["scripts_directory"], "WS_BAD_NAME__fix.ps1"
        )
        self.assertTrue(os.path.exists(expected_fix))


class TestSiemExporter(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scan = _make_scan(findings=[
            _make_finding(),
            _make_finding("WS-FW-001", status=FindingStatus.WARN),
            _make_finding("WS-UAC-001", status=FindingStatus.PASS),
        ])

    def tearDown(self):
        self.temp_dir.cleanup()

    def _read_ndjson(self, path):
        with open(path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def test_splunk_export_excludes_pass_findings(self):
        path = SiemExporter.export(self.scan, self.temp_dir.name, platform="splunk")
        events = self._read_ndjson(path)
        self.assertEqual(len(events), 2)  # FAIL + WARN only
        ids = {e["winsecure.finding_id"] for e in events}
        self.assertNotIn("WS-UAC-001", ids)
        self.assertEqual(events[0]["sourcetype"], "winsecure:assessment")

    def test_elastic_export_has_ecs_fields(self):
        path = SiemExporter.export(self.scan, self.temp_dir.name, platform="elastic")
        events = self._read_ndjson(path)
        self.assertTrue(all("event.severity" in e for e in events))
        self.assertTrue(all("event.outcome" in e for e in events))
        fail_event = next(e for e in events if e["winsecure.finding_id"] == "WS-DEF-001")
        self.assertEqual(fail_event["event.outcome"], "failure")

    def test_sentinel_export_has_sentinel_fields(self):
        path = SiemExporter.export(self.scan, self.temp_dir.name, platform="sentinel")
        events = self._read_ndjson(path)
        self.assertTrue(all("TimeGenerated" in e for e in events))
        self.assertTrue(all("RemediationSteps" in e for e in events))

    def test_unknown_platform_returns_none(self):
        result = SiemExporter.export(self.scan, self.temp_dir.name, platform="qradar")
        self.assertIsNone(result)

    def test_resolve_platforms_all(self):
        self.assertEqual(
            SiemExporter.resolve_platforms("all"),
            ["splunk", "elastic", "sentinel"],
        )

    def test_resolve_platforms_single(self):
        self.assertEqual(SiemExporter.resolve_platforms("Splunk"), ["splunk"])

    def test_resolve_platforms_unknown_is_empty(self):
        self.assertEqual(SiemExporter.resolve_platforms("qradar"), [])

    def test_export_all_platforms_writes_three_files(self):
        paths = SiemExporter.export_all_platforms(self.scan, self.temp_dir.name)
        self.assertEqual(len(paths), 3)
        for p in paths.values():
            self.assertTrue(os.path.exists(p))


class TestV2CliCommands(unittest.TestCase):
    def setUp(self):
        self.parser = create_cli_parser()

    def test_api_command_parses(self):
        args = self.parser.parse_args(["api", "--port", "9000", "--token", "secret",
                                       "--webhook", "https://example.com/hook"])
        self.assertEqual(args.command, "api")
        self.assertEqual(args.port, 9000)
        self.assertEqual(args.token, "secret")
        self.assertEqual(args.webhook, ["https://example.com/hook"])

    def test_trend_command_parses(self):
        args = self.parser.parse_args(["trend", "--limit", "5", "--json"])
        self.assertEqual(args.command, "trend")
        self.assertEqual(args.limit, 5)
        self.assertTrue(args.json)

    def test_scan_v2_flags_parse(self):
        args = self.parser.parse_args([
            "scan", "--emit-scripts", "--siem", "splunk",
            "--webhook", "https://a.com/x", "--webhook", "https://b.com/y",
        ])
        self.assertTrue(args.emit_scripts)
        self.assertEqual(args.siem, "splunk")
        self.assertEqual(args.webhook, ["https://a.com/x", "https://b.com/y"])

    def test_webhook_dispatcher_registers_dedupes(self):
        from winsecure.cli.api_server import WebhookDispatcher
        d = WebhookDispatcher()
        d.register("https://a.com/hook")
        d.register("https://a.com/hook")
        self.assertEqual(len(d.endpoints), 1)

    def test_webhook_dispatch_empty_endpoints(self):
        from winsecure.cli.api_server import WebhookDispatcher
        d = WebhookDispatcher()
        results = d.dispatch({"event": "test"})
        self.assertEqual(results, [])


class TestApiServerHttp(unittest.TestCase):
    """Live HTTP tests against a background ApiServer on an ephemeral port."""

    @classmethod
    def setUpClass(cls):
        from winsecure.cli.api_server import ApiServer, ApiRequestHandler
        cls._handler_cls = ApiRequestHandler
        cls.server = ApiServer(
            db_path=os.path.join(tempfile.mkdtemp(prefix="ws_api_"), "api.db"),
            port=0,
            host="127.0.0.1",
            api_token="test-token",
        )
        cls.server.start_background()
        cls.port = cls.server.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        # Reset class-level handler state so other tests are unaffected
        cls._handler_cls.repository = None
        cls._handler_cls.db_manager = None
        cls._handler_cls.trend_engine = None
        cls._handler_cls.webhook_dispatcher = None
        cls._handler_cls.api_token = None

    def _get(self, path, token=None):
        from urllib import request as urllib_request
        from urllib.error import HTTPError
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib_request.Request(url)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib_request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8") or "{}")

    def test_index_lists_endpoints(self):
        status, body = self._get("/", token="test-token")
        self.assertEqual(status, 200)
        self.assertIn("endpoints", body)

    def test_missing_token_is_unauthorized(self):
        status, _ = self._get("/api/scans")
        self.assertEqual(status, 401)

    def test_valid_token_grants_access(self):
        status, body = self._get("/api/scans", token="test-token")
        self.assertEqual(status, 200)
        self.assertIn("scans", body)

    def test_invalid_limit_returns_400(self):
        status, body = self._get("/api/scans?limit=abc", token="test-token")
        self.assertEqual(status, 400)
        self.assertIn("limit", body["error"])

    def test_out_of_range_limit_returns_400(self):
        status, _ = self._get("/api/scans?limit=9999", token="test-token")
        self.assertEqual(status, 400)

    def test_findings_endpoint_respects_limit(self):
        status, body = self._get("/api/findings?limit=5", token="test-token")
        self.assertEqual(status, 200)
        self.assertLessEqual(body["count"], 5)

    def test_unknown_route_returns_404(self):
        status, _ = self._get("/api/nope", token="test-token")
        self.assertEqual(status, 404)


class TestFullSuiteRunner(unittest.TestCase):
    """Tests the `python run.py suite` orchestrator with stubbed stages."""

    @staticmethod
    def _load_suite_module():
        import importlib.util
        suite_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "scripts", "run_suite.py",
        )
        spec = importlib.util.spec_from_file_location("run_suite_under_test", suite_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _run_quiet(self, mod, **kwargs):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = mod.run_suite(**kwargs)
        return code, buf.getvalue()

    def test_all_stages_pass_returns_zero(self):
        mod = self._load_suite_module()
        mod.step_integrity = lambda: (True, "ok")
        mod.step_fixture_scan = lambda: (True, "ok")
        mod.step_plugins = lambda: (True, "ok")
        code, output = self._run_quiet(mod, include_tests=False, include_benchmark=False)
        self.assertEqual(code, 0)
        self.assertIn("3/3 stages passed", output)

    def test_failing_stage_returns_nonzero(self):
        mod = self._load_suite_module()
        mod.step_integrity = lambda: (True, "ok")
        mod.step_fixture_scan = lambda: (False, "artifacts missing")
        mod.step_plugins = lambda: (True, "ok")
        code, output = self._run_quiet(mod, include_tests=False, include_benchmark=False)
        self.assertEqual(code, 1)
        self.assertIn("FAIL", output)

    def test_stage_exception_counts_as_failure(self):
        mod = self._load_suite_module()
        mod.step_integrity = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        mod.step_fixture_scan = lambda: (True, "ok")
        mod.step_plugins = lambda: (True, "ok")
        code, output = self._run_quiet(mod, include_tests=False, include_benchmark=False)
        self.assertEqual(code, 1)
        self.assertIn("RuntimeError: boom", output)

    def test_benchmark_flag_adds_stage(self):
        mod = self._load_suite_module()
        mod.step_integrity = lambda: (True, "ok")
        mod.step_fixture_scan = lambda: (True, "ok")
        mod.step_plugins = lambda: (True, "ok")
        mod.step_benchmark = lambda: (True, "ok")
        code, output = self._run_quiet(mod, include_tests=False, include_benchmark=True)
        self.assertEqual(code, 0)
        self.assertIn("4/4 stages passed", output)

    def test_run_py_suite_help_parses(self):
        import subprocess
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        res = subprocess.run(
            [sys.executable, os.path.join(root, "run.py"), "suite", "--help"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("--skip-tests", res.stdout)
        self.assertIn("--benchmark", res.stdout)


class TestKnowledgeBaseLinks(unittest.TestCase):
    """Report-to-website deep links and site/generator ID consistency."""

    def test_deep_dive_url_resolves_for_firewall_finding(self):
        from winsecure.reporting.web_generator import WebReportGenerator
        url = WebReportGenerator.deep_dive_url("WS-FW-001")
        self.assertEqual(url, "https://kartavyajoshi.github.io/WINSECURE/#finding-WS-FW-001")

    def test_deep_dive_url_none_for_undocumented_finding(self):
        from winsecure.reporting.web_generator import WebReportGenerator
        self.assertIsNone(WebReportGenerator.deep_dive_url("WS-FW-003"))

    def test_generated_report_contains_deep_dive_link(self):
        from winsecure.reporting.web_generator import WebReportGenerator
        scan = _make_scan(findings=[_make_finding(fid="WS-FW-001")])
        with tempfile.TemporaryDirectory() as tmp:
            index_path = WebReportGenerator.generate(scan, tmp)
            with open(index_path, encoding="utf-8") as fh:
                html_text = fh.read()
            self.assertIn("#finding-WS-FW-001", html_text)

            js_path = os.path.join(tmp, "report.js")
            with open(js_path, encoding="utf-8") as fh:
                js_text = fh.read()
            self.assertIn("DEEP_DIVE_IDS", js_text)
            self.assertIn("https://kartavyajoshi.github.io/WINSECURE/", js_text)
            self.assertNotIn("__DEEP_DIVE_IDS_JSON__", js_text)
            self.assertNotIn("__SITE_URL__", js_text)

    def test_website_deep_dive_ids_match_generator(self):
        """The site knowledge base and the report generator must stay in sync."""
        import re
        from winsecure.reporting.web_generator import WebReportGenerator
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "index.html"), encoding="utf-8") as fh:
            site_html = fh.read()
        start = site_html.index("FINDING_DEEP_DIVES = [")
        end = site_html.index("];", start)
        site_ids = set(re.findall(r'id:\s*"(WS-[A-Z]+-\d+)"', site_html[start:end]))
        self.assertTrue(site_ids, "No deep-dive IDs found in website")
        self.assertEqual(site_ids, set(WebReportGenerator.DEEP_DIVE_FINDING_IDS))


if __name__ == "__main__":
    unittest.main()
