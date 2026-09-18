"""
WinSecure Command Line Argument Parser
"""
import argparse
from winsecure.version import __version__, __product_name__, __description__


def create_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="winsecure",
        description=f"{__product_name__} v{__version__} — {__description__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: scan (Primary default workflow)
    scan_parser = subparsers.add_parser("scan", help="Run complete Windows security assessment")
    scan_parser.add_argument("--output", "-o", default="./WinSecure-Report", help="Target directory for generated reports (default: ./WinSecure-Report)")
    scan_parser.add_argument("--profile", "-p", default="standard", choices=["standard", "hardened", "quick", "full"], help="Scan profile level")
    scan_parser.add_argument("--fixture", help="Path to synthetic test fixture JSON (for offline / CI simulation)")
    scan_parser.add_argument("--db", help="Path to SQLite history database file")
    scan_parser.add_argument("--format", default="html,json,csv,sarif,md", help="Comma-separated output report formats")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Display verbose real-time test execution details and evidence")
    scan_parser.add_argument("--debug", "-d", action="store_true", help="Display full debugging telemetry and execution diagnostics")
    scan_parser.add_argument("--serve", "-s", action="store_true", help="Automatically launch local web server and open dashboard in browser")
    scan_parser.add_argument("--port", type=int, default=8080, help="Port to use if --serve is specified (default: 8080)")
    scan_parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")
    scan_parser.add_argument("--no-log", action="store_true", help="Disable writing file logs")

    # v2 scan options
    scan_parser.add_argument("--siem", choices=["splunk", "elastic", "sentinel", "all"], default="all", help="SIEM NDJSON export platform (v2, default: all)")
    scan_parser.add_argument("--emit-scripts", action="store_true", help="Emit executable PowerShell remediation scripts (v2)")
    scan_parser.add_argument("--webhook", action="append", default=[], help="Webhook URL to notify on scan completion (repeatable, v2)")
    scan_parser.add_argument("--api-token", help="Bearer token required by the API server (v2)")

    # Command: serve (Serve existing report dashboard)
    serve_parser = subparsers.add_parser("serve", help="Launch local HTTP server to view the security dashboard")
    serve_parser.add_argument("--dir", "-d", default="./WinSecure-Report", help="Path to directory containing generated web report (default: ./WinSecure-Report)")
    serve_parser.add_argument("--port", "-p", type=int, default=8080, help="HTTP port to bind (default: 8080)")
    serve_parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")

    # Command: benchmark
    bench_parser = subparsers.add_parser("benchmark", help="Execute automated performance and throughput benchmarks")
    bench_parser.add_argument("--iterations", "-i", type=int, default=5, help="Number of benchmark iterations per profile (default: 5)")
    bench_parser.add_argument("--json", action="store_true", help="Output raw JSON benchmark metrics")

    # Command: demo (Launch synthetic demonstration mode)
    demo_parser = subparsers.add_parser("demo", help="Launch synthetic assessment demonstration dashboard")
    demo_parser.add_argument("--port", "-p", type=int, default=8080, help="HTTP port to bind (default: 8080)")
    demo_parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")

    # Command: api (v2 — REST API & webhook server)
    api_parser = subparsers.add_parser("api", help="Launch the WinSecure REST API & webhook server (v2)")
    api_parser.add_argument("--db", help="Path to SQLite history database file")
    api_parser.add_argument("--port", "-p", type=int, default=8443, help="HTTP port to bind (default: 8443)")
    api_parser.add_argument("--host", default="127.0.0.1", help="Interface to bind (default: 127.0.0.1)")
    api_parser.add_argument("--token", help="Require bearer token authentication for API access")
    api_parser.add_argument("--webhook", action="append", default=[], help="Register a webhook endpoint URL (repeatable)")
    api_parser.add_argument("--no-browser", action="store_true", help="Do not automatically open API docs in browser")

    # Command: trend (v2 — historical drift & trend analysis)
    trend_parser = subparsers.add_parser("trend", help="Analyze security posture trends across scan history (v2)")
    trend_parser.add_argument("--db", help="Path to SQLite history database file")
    trend_parser.add_argument("--limit", "-n", type=int, default=20, help="Maximum scans to analyze (default: 20)")
    trend_parser.add_argument("--json", action="store_true", help="Output raw JSON trend metrics")

    # Command: plugins (v2.1 — plugin management)
    plugins_parser = subparsers.add_parser("plugins", help="List installed WinSecure plugins (v2.1)")
    plugins_parser.add_argument("--json", action="store_true", help="Output plugin registry as JSON")

    # Command: compare (v2.5 — empirical comparative benchmarking)
    compare_parser = subparsers.add_parser("compare", help="Display empirical comparison against previous versions and industry tools (v2.5)")
    compare_parser.add_argument("--json", action="store_true", help="Output comparative metrics as JSON")

    # Command: version
    subparsers.add_parser("version", help="Show WinSecure version and product metadata")

    # Command: help
    subparsers.add_parser("help", help="Display comprehensive usage assistance")

    return parser
