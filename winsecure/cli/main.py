"""
WinSecure CLI Main Entrypoint with Real-Time Verbose Streaming
"""
import json
import sys
import os
import time
from datetime import datetime, timezone

# Ensure line-buffering on stdout for immediate real-time terminal output
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

from winsecure.cli.parser import create_cli_parser
from winsecure.cli.formatter import CliFormatter
from winsecure.cli.server import start_server
from winsecure.core.config import ScanConfig
from winsecure.core.context import ScanContext
from winsecure.core.logger import setup_logger
from winsecure.engine.pipeline import ScanPipeline
from winsecure.reporting.generator import ReportGenerator
from winsecure.benchmarking.benchmark_suite import BenchmarkSuite
from winsecure.version import __version__, __product_name__, __codename__, __description__
from winsecure.utils.formatting import Colors, colorize
from winsecure.core.health import HealthChecker


def main(argv=None):
    parser = create_cli_parser()
    args = parser.parse_args(argv)

    if not args.command or args.command == "help":
        parser.print_help()
        return 0

    if args.command == "version":
        print(f"{__product_name__} v{__version__} ({__codename__})", flush=True)
        print(f"{__description__}", flush=True)
        return 0

    if args.command == "demo":
        site_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "docs", "site")
        if not os.path.exists(site_dir):
            site_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "web")
        if not os.path.exists(site_dir):
            site_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        print("[*] Launching WinSecure Synthetic Demonstration Platform...", flush=True)
        print("[*] Target Host: LAB-WIN-042 (Security Assessment Lab)", flush=True)
        print("[*] Demonstration Mode: 100% Synthetic Assessment Data", flush=True)
        start_server(
            directory=site_dir,
            port=args.port,
            open_browser=not args.no_browser,
        )
        return 0

    if args.command == "serve":
        start_server(
            directory=args.dir,
            port=args.port,
            open_browser=not args.no_browser,
        )
        return 0

    if args.command == "benchmark":
        print(colorize(f"\n[*] Executing WinSecure Benchmark Suite (Iterations: {args.iterations})...", Colors.BOLD), flush=True)
        bench_data = BenchmarkSuite.run_benchmark(iterations=args.iterations)

        if args.json:
            print(json.dumps(bench_data, indent=2), flush=True)
            return 0

        tp_str = f"{bench_data['overall_throughput_checks_per_sec']} checks/sec"
        mem_str = f"{bench_data['peak_memory_rss_mb']} MB RSS"
        cpu_str = f"{bench_data['average_cpu_percent']}%"

        print(colorize("------------------------------------------------------------", Colors.DIM), flush=True)
        print(f"Total Modules Benchmarked: {colorize(str(bench_data['total_modules_benchmarked']), Colors.BOLD)}", flush=True)
        print(f"Overall Throughput:        {colorize(tp_str, Colors.GREEN + Colors.BOLD)}", flush=True)
        print(f"Peak Memory Footprint:     {colorize(mem_str, Colors.CYAN)}", flush=True)
        print(f"Average CPU Utilization:   {colorize(cpu_str, Colors.CYAN)}", flush=True)
        print(colorize("------------------------------------------------------------", Colors.DIM), flush=True)
        print(colorize("\nProfile Performance Breakdown:", Colors.BOLD), flush=True)
        for p in bench_data["profile_benchmarks"]:
            print(f"  * {p['profile'].ljust(10)}: {p['average_duration_sec']:.4f}s avg | {p['checks_evaluated']} checks | {p['throughput_checks_per_sec']} checks/s | Score: {p['resulting_security_score']}/100", flush=True)

        print(colorize("\nFastest Module Latencies (Top 5):", Colors.BOLD), flush=True)
        sorted_mods = sorted(bench_data["module_latencies_ms"].items(), key=lambda kv: kv[1])
        for name, lat in sorted_mods[:5]:
            print(f"  * {name.ljust(22)}: {lat:.3f} ms", flush=True)
        print(flush=True)
        return 0

    if args.command == "scan":
        config = ScanConfig(
            profile=args.profile,
            output_dir=args.output,
            fixture_path=args.fixture,
            db_path=args.db,
        )

        context = ScanContext(config=config)
        pipeline = ScanPipeline(context=context)

        # Setup Logging
        log_file = None
        if not getattr(args, "no_log", False):
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            logs_dir = os.path.join(base_dir, "logs")
            os.makedirs(logs_dir, exist_ok=True)
            log_file = os.path.join(logs_dir, "latest.log")
            ts_str = datetime.now().strftime("%Y-%m-%d-%H%M%S")
            ts_log = os.path.join(logs_dir, f"scan-{ts_str}.log")
            
        logger = setup_logger(
            name="winsecure",
            log_file=log_file,
        )

        logger.info(f"Scan started | Profile: {config.profile} | Output: {config.output_dir}")

        CliFormatter.print_banner()
        CliFormatter.print_scan_init(context)

        # ---- v2.1: Plugin subsystem -------------------------------------
        from winsecure.plugins.loader import PluginRegistry
        plugin_registry = PluginRegistry()
        plugin_dirs = [os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "plugins"
        )]
        plugin_registry.discover(plugin_dirs)
        if plugin_registry.plugins:
            print(colorize(f"[*] Plugins loaded: {', '.join(plugin_registry.plugins.keys())}", Colors.CYAN), flush=True)
            plugin_registry.dispatch_init(context)
            plugin_registry.dispatch_pre_scan(context)

        # Pre-Flight Self-Diagnostic Subsystem Check
        self_check_results = HealthChecker.run_self_check(config)
        CliFormatter.print_self_check(self_check_results)

        # Callbacks for real-time terminal streaming
        print(colorize("[SECURITY TELEMETRY COLLECTION]", Colors.BOLD), flush=True)

        def on_collector(idx, total, name, dur):
            CliFormatter.print_collector_step(idx, total, name, dur)
            logger.info(f"Collector {idx}/{total} {name}: completed in {dur:.2f}s")

        def on_module(idx, total, name, cat):
            CliFormatter.print_module_start(idx, total, name, cat)
            logger.info(f"Module {idx}/{total} started: {name} ({cat})")

        def on_test(finding, idx, total, stats):
            CliFormatter.print_test_result(
                finding=finding,
                current_idx=idx,
                total_tests=total,
                verbose=getattr(args, "verbose", False),
                debug=getattr(args, "debug", False),
            )
            logger.info(f"Test {idx}/{total} [{finding.status.value}] {finding.id}: {finding.title} ({finding.duration:.3f}s)")

        def on_step(idx, total, desc):
            logger.debug(f"Pipeline stage {idx}/{total}: {desc}")

        # Execute 8-stage assessment pipeline with live streaming
        scan_result = pipeline.run(
            progress_callback=on_step,
            test_callback=on_test,
            module_callback=on_module,
            collector_callback=on_collector,
        )

        # Print Live Progress Summary
        final_stats = pipeline.result_collector.get_stats()
        print("\n------------------------------------------------------------", flush=True)
        CliFormatter.print_live_progress(final_stats)
        print("------------------------------------------------------------", flush=True)

        # ---- v2.1: Plugin post_scan / post_finding hooks -----------------
        # post_scan lets plugins mutate the ScanResult (e.g. anonymize host data)
        # before reports are generated; post_finding filters each finding dict.
        if plugin_registry.plugins:
            from winsecure.plugins.base import PluginHook
            scan_result = plugin_registry.dispatch_post_scan(scan_result)

            if plugin_registry.has_hook_subscribers(PluginHook.POST_FINDING):
                from winsecure.models.finding import Finding as FindingModel
                updated = []
                for finding in scan_result.findings:
                    enriched = plugin_registry.dispatch_post_finding(finding.to_dict(), context)
                    try:
                        updated.append(FindingModel.from_dict(enriched))
                    except Exception as e:
                        logger.warning(f"Plugin post_finding output rejected for {finding.id}: {e}")
                        updated.append(finding)
                scan_result.findings = updated

        # Generate complete report website and machine exports
        index_path = ReportGenerator.generate_all(
            scan_result, config.output_dir, siem=getattr(args, "siem", "all")
        )
        logger.info(f"Reports generated successfully at {config.output_dir}")

        # ---- v2.1: Plugin on_report hook (report URL distribution) ------
        if plugin_registry.plugins:
            report_info = {
                "index_url": "file://" + index_path.replace("\\", "/"),
                "output_dir": config.output_dir,
                "scan_id": scan_result.scan_id,
                "score": scan_result.security_score,
                "risk_level": scan_result.risk_level.value if hasattr(scan_result.risk_level, "value") else str(scan_result.risk_level),
            }
            plugin_registry.dispatch_on_report(report_info)
            for err in plugin_registry.load_errors:
                logger.warning(f"Plugin issue [{err.get('plugin')}]: {err.get('error')}")

        # ---- v2: Auto-remediation script emission -----------------------
        if getattr(args, "emit_scripts", False):
            try:
                from winsecure.remediation.script_generator import RemediationScriptGenerator
                script_info = RemediationScriptGenerator(config.output_dir).generate_bundle(scan_result)
                print(colorize(
                    f"\n[*] Remediation Scripts: {script_info['script_count']} bundles -> {script_info['scripts_directory']}",
                    Colors.CYAN,
                ), flush=True)
                logger.info(f"Remediation scripts emitted: {script_info['run_all_script']}")
            except Exception as e:
                logger.warning(f"Remediation script generation failed: {e}")

        # ---- v2: Webhook notifications ----------------------------------
        webhook_urls = getattr(args, "webhook", None) or []
        if webhook_urls:
            from winsecure.cli.api_server import WebhookDispatcher
            dispatcher = WebhookDispatcher()
            for url in webhook_urls:
                dispatcher.register(url)
            delivery_results = dispatcher.notify_scan_complete({
                "scan_id": scan_result.scan_id,
                "security_score": scan_result.security_score,
                "risk_level": scan_result.risk_level.value if hasattr(scan_result.risk_level, "value") else str(scan_result.risk_level),
                "profile": scan_result.profile,
                "total_findings": len(scan_result.findings),
                "report_url": index_path,
            })
            for r in delivery_results:
                state = colorize("DELIVERED", Colors.GREEN) if r["delivered"] else colorize(f"FAILED ({r.get('error')})", Colors.YELLOW)
                print(f"[*] Webhook {r['url']}: {state}", flush=True)

        # Post-Flight Diagnostic Verification
        post_ok, post_msg = HealthChecker.post_flight_check(scan_result, index_path)
        if post_ok:
            print(colorize(f"\n[*] Diagnostic Integrity: [VERIFIED] ({post_msg})", Colors.GREEN), flush=True)
        else:
            print(colorize(f"\n[!] Diagnostic Warning: {post_msg}", Colors.YELLOW), flush=True)

        # Print comprehensive final summary
        CliFormatter.print_summary(scan_result, index_path)

        if getattr(args, "serve", False):
            start_server(
                directory=config.output_dir,
                port=getattr(args, "port", 8080),
                open_browser=True,
            )

        return 0

    # ---- v2: REST API & webhook server ----------------------------------
    if args.command == "api":
        from winsecure.cli.api_server import ApiServer
        db_path = args.db
        if not db_path:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            db_path = os.path.join(base_dir, "logs", "winsecure_history.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        server = ApiServer(
            db_path=db_path,
            port=args.port,
            host=args.host,
            api_token=args.token,
        )
        for url in (args.webhook or []):
            server.webhook_dispatcher.register(url)
        try:
            server.start(open_browser=not args.no_browser)
        except KeyboardInterrupt:
            pass
        except OSError as e:
            print(colorize(f"[!] API server failed to start: {e}", Colors.RED), flush=True)
            return 1
        finally:
            server.stop()
        return 0

    # ---- v2: Drift & trend analysis --------------------------------------
    if args.command == "trend":
        from winsecure.analytics.drift_trend import DriftTrendEngine
        db_path = args.db
        if not db_path:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            db_path = os.path.join(base_dir, "logs", "winsecure_history.db")

        if not os.path.exists(db_path):
            print(colorize("[!] No scan history database found. Run 'winsecure scan' first.", Colors.YELLOW), flush=True)
            return 1

        engine = DriftTrendEngine(db_path)
        try:
            report = engine.build_full_report(limit=args.limit)
        finally:
            engine.close()

        if args.json:
            print(json.dumps(report, indent=2), flush=True)
            return 0

        if not report.get("has_history"):
            print(colorize(f"[!] {report.get('message')}", Colors.YELLOW), flush=True)
            return 1

        print(colorize(f"\n[*] WinSecure Posture Trend Analysis ({report['scans_analyzed']} scans)", Colors.BOLD), flush=True)
        print(colorize("------------------------------------------------------------", Colors.DIM), flush=True)
        direction = report["direction"]
        dir_color = Colors.GREEN if direction == "IMPROVING" else (Colors.RED if direction == "DECLINING" else Colors.CYAN)
        print(f"  Trend Direction:   {colorize(direction, dir_color + Colors.BOLD)}", flush=True)
        net_change_str = f"{report['net_change']:+.1f} pts"
        print(f"  Net Change:        {colorize(net_change_str, dir_color)}  (first {report['first_score']} -> last {report['last_score']})", flush=True)
        print(f"  Average Score:     {report['average_score']}", flush=True)
        print(f"  Best / Worst:      {report['best_score']} / {report['worst_score']}", flush=True)
        print(f"  Volatility Range:  {report['volatility']} pts", flush=True)
        print(f"  Improving Steps:   {report['improving_steps']}", flush=True)
        print(f"  Declining Steps:   {report['declining_steps']}", flush=True)
        recurring = report.get("recurring_failures") or []
        if recurring:
            print(colorize("\n  Recurring Failures (chronic defects):", Colors.BOLD), flush=True)
            for entry in recurring[:10]:
                print(f"    * {entry['finding_id'].ljust(14)} failed {entry['occurrences']}x across history", flush=True)
        else:
            print(colorize("\n  No chronic recurring failures detected.", Colors.GREEN), flush=True)
        print(colorize("------------------------------------------------------------", Colors.DIM), flush=True)
        return 0

    # ---- v2.1: Plugin management -----------------------------------------
    if args.command == "plugins":
        from winsecure.plugins.loader import PluginRegistry
        registry = PluginRegistry()
        plugin_dirs = [os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "plugins"
        )]
        registry.discover(plugin_dirs)
        listing = registry.list_plugins()

        if args.json:
            print(json.dumps({"plugins": listing, "load_errors": registry.load_errors}, indent=2), flush=True)
            return 0

        if not listing:
            print(colorize("[!] No plugins found in ./plugins directory.", Colors.YELLOW), flush=True)
            return 0

        print(colorize(f"\n[*] WinSecure Plugin Registry ({len(listing)} loaded)", Colors.BOLD), flush=True)
        print(colorize("------------------------------------------------------------", Colors.DIM), flush=True)
        for p in listing:
            state = colorize("ENABLED ", Colors.GREEN) if p["enabled"] else colorize("DISABLED", Colors.YELLOW)
            print(f"  {p['plugin_id'].ljust(20)} v{p['version'].ljust(8)} {state}  {p['name']}", flush=True)
            if p.get("description"):
                print(f"  {'':20} {p['description'][:70]}", flush=True)
            if p.get("hooks"):
                print(f"  {'':20} hooks: {', '.join(p['hooks'])}", flush=True)
        for err in registry.load_errors:
            print(colorize(f"  [!] Load error [{err.get('plugin')}]: {err.get('error')}", Colors.RED), flush=True)
        print(colorize("------------------------------------------------------------", Colors.DIM), flush=True)
        return 0

    # ---- v2.5: Empirical Comparative Benchmarking ------------------------
    if args.command == "compare":
        from winsecure.comparison.evaluation import ComparativeEvaluationEngine
        if getattr(args, "json", False):
            payload = {
                "version_evolution": ComparativeEvaluationEngine.get_version_evolution(),
                "industry_benchmark": ComparativeEvaluationEngine.get_industry_benchmark(),
            }
            print(json.dumps(payload, indent=2), flush=True)
            return 0

        print(ComparativeEvaluationEngine.format_cli_comparison(), flush=True)
        return 0

    # ---- v2.5: Native Desktop GUI Control Cockpit ------------------------
    if args.command == "gui":
        from winsecure.gui.app import launch_gui
        report_dir = getattr(args, "report_dir", "./WinSecure-Report")
        autostart = getattr(args, "scan", False)
        launch_gui(report_dir=report_dir, autostart_scan=autostart)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
