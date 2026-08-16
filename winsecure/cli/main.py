"""
WinSecure CLI Main Entrypoint with Real-Time Verbose Streaming
"""
import json
import sys
import os
import time
from datetime import datetime, timezone
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
        print(f"{__product_name__} v{__version__} ({__codename__})")
        print(f"{__description__}")
        return 0

    if args.command == "demo":
        site_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "docs", "site")
        if not os.path.exists(site_dir):
            site_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "web")
        print("[*] Launching WinSecure Synthetic Demonstration Platform...")
        print("[*] Target Host: LAB-WIN-042 (Security Assessment Lab)")
        print("[*] Demonstration Mode: 100% Synthetic Assessment Data")
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
        print(colorize(f"\n[*] Executing WinSecure Benchmark Suite (Iterations: {args.iterations})...", Colors.BOLD))
        bench_data = BenchmarkSuite.run_benchmark(iterations=args.iterations)

        if args.json:
            print(json.dumps(bench_data, indent=2))
            return 0

        tp_str = f"{bench_data['overall_throughput_checks_per_sec']} checks/sec"
        mem_str = f"{bench_data['peak_memory_rss_mb']} MB RSS"
        cpu_str = f"{bench_data['average_cpu_percent']}%"

        print(colorize("------------------------------------------------------------", Colors.DIM))
        print(f"Total Modules Benchmarked: {colorize(str(bench_data['total_modules_benchmarked']), Colors.BOLD)}")
        print(f"Overall Throughput:        {colorize(tp_str, Colors.GREEN + Colors.BOLD)}")
        print(f"Peak Memory Footprint:     {colorize(mem_str, Colors.CYAN)}")
        print(f"Average CPU Utilization:   {colorize(cpu_str, Colors.CYAN)}")
        print(colorize("------------------------------------------------------------", Colors.DIM))
        print(colorize("\nProfile Performance Breakdown:", Colors.BOLD))
        for p in bench_data["profile_benchmarks"]:
            print(f"  * {p['profile'].ljust(10)}: {p['average_duration_sec']:.4f}s avg | {p['checks_evaluated']} checks | {p['throughput_checks_per_sec']} checks/s | Score: {p['resulting_security_score']}/100")

        print(colorize("\nFastest Module Latencies (Top 5):", Colors.BOLD))
        sorted_mods = sorted(bench_data["module_latencies_ms"].items(), key=lambda kv: kv[1])
        for name, lat in sorted_mods[:5]:
            print(f"  * {name.ljust(22)}: {lat:.3f} ms")
        print()
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
            # Also write timestamped log
            ts_str = datetime.now().strftime("%Y-%m-%d-%H%M%S")
            ts_log = os.path.join(logs_dir, f"scan-{ts_str}.log")
            
        logger = setup_logger(
            name="winsecure",
            log_file=log_file,
        )

        logger.info(f"Scan started | Profile: {config.profile} | Output: {config.output_dir}")

        CliFormatter.print_banner()
        CliFormatter.print_scan_init(context)

        # Pre-Flight Self-Diagnostic Subsystem Check
        self_check_results = HealthChecker.run_self_check(config)
        CliFormatter.print_self_check(self_check_results)

        # Callbacks for real-time terminal streaming
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
        )

        # Print Live Progress Summary
        final_stats = pipeline.result_collector.get_stats()
        print("\n------------------------------------------------------------")
        CliFormatter.print_live_progress(final_stats)
        print("------------------------------------------------------------")

        # Generate complete report website and machine exports
        index_path = ReportGenerator.generate_all(scan_result, config.output_dir)
        logger.info(f"Reports generated successfully at {config.output_dir}")

        # Post-Flight Diagnostic Verification
        post_ok, post_msg = HealthChecker.post_flight_check(scan_result, index_path)
        if post_ok:
            print(colorize(f"\n[*] Diagnostic Integrity: [VERIFIED] ({post_msg})", Colors.GREEN))
        else:
            print(colorize(f"\n[!] Diagnostic Warning: {post_msg}", Colors.YELLOW))

        # Print comprehensive final summary
        CliFormatter.print_summary(scan_result, index_path)

        if getattr(args, "serve", False):
            start_server(
                directory=config.output_dir,
                port=getattr(args, "port", 8080),
                open_browser=True,
            )

        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
