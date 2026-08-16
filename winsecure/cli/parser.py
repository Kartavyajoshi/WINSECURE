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
    scan_parser.add_argument("--format", default="html,json,csv,sqlite,web", help="Comma-separated output report formats")
    scan_parser.add_argument("--serve", "-s", action="store_true", help="Automatically launch local web server and open Wazuh-style dashboard in browser")
    scan_parser.add_argument("--port", type=int, default=8080, help="Port to use if --serve is specified (default: 8080)")
    scan_parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")

    # Command: serve (Serve existing report dashboard)
    serve_parser = subparsers.add_parser("serve", help="Launch local HTTP server to view the Wazuh-style security dashboard")
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

    # Command: version
    subparsers.add_parser("version", help="Show WinSecure version and product metadata")

    # Command: help
    subparsers.add_parser("help", help="Display comprehensive usage assistance")

    return parser
