#!/usr/bin/env python3
"""
WinSecure Single-Command Management Launcher
Enables unified execution for Demo Mode, System Scans, Benchmarking, and Server Hosting.
"""
import sys
import os
import argparse
import subprocess

# Ensure winsecure package is discoverable from root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def check_environment():
    """Verify python runtime dependencies and version requirements."""
    if sys.version_info < (3, 9):
        print(f"[ERROR] WinSecure requires Python 3.9 or newer. Detected: {sys.version}")
        sys.exit(1)


def cmd_demo(args):
    """Launch the zero-configuration Synthetic Demonstration Platform."""
    from winsecure.cli.server import start_server

    print("[*] Initializing WinSecure Synthetic Demonstration Platform...")
    print("[*] Environment: Security Assessment Lab (LAB-WIN-042)")
    print("[*] Dataset: 100% Synthetic Assessment Data")
    print(f"[*] Starting local server on http://127.0.0.1:{args.port}/")

    site_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs", "site")
    if not os.path.exists(site_dir):
        site_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

    start_server(
        directory=site_dir,
        port=args.port,
        open_browser=not args.no_browser,
    )


def cmd_scan(args):
    """Execute assessment pipeline."""
    from winsecure.cli.main import main
    return main(["scan"] + sys.argv[2:])


def cmd_benchmark(args):
    """Execute synthetic benchmark suite."""
    from winsecure.cli.main import main
    return main(["benchmark"] + sys.argv[2:])


def cmd_test(args):
    """Run unit and integration test suite."""
    print("[*] Running WinSecure Test Suite...")
    res = subprocess.run([sys.executable, "-m", "unittest", "discover", "tests"])
    sys.exit(res.returncode)


def cmd_serve(args):
    """Host an existing assessment report directory."""
    from winsecure.cli.server import start_server
    start_server(
        directory=args.dir,
        port=args.port,
        open_browser=not args.no_browser,
    )


def main():
    check_environment()

    parser = argparse.ArgumentParser(
        prog="run.py",
        description="WinSecure Security Assessment & Analysis Platform Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py demo                      # Launch synthetic demonstration dashboard
  python run.py scan --profile full       # Execute full system security scan
  python run.py benchmark                 # Run synthetic benchmark throughput tests
  python run.py test                      # Run unit test suite
  python run.py serve --dir ./docs/site   # Host platform documentation portal
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Demo command
    p_demo = subparsers.add_parser("demo", help="Launch synthetic assessment demonstration")
    p_demo.add_argument("--port", type=int, default=8080, help="Port to bind server (default: 8080)")
    p_demo.add_argument("--no-browser", action="store_true", help="Do not automatically open browser")

    # Scan command
    p_scan = subparsers.add_parser("scan", help="Run security assessment scan")
    p_scan.add_argument("--profile", default="standard", help="Assessment profile (standard, fast, full)")
    p_scan.add_argument("--output", default="./WinSecure-Report", help="Output directory")
    p_scan.add_argument("--serve", action="store_true", help="Start web server after scan")
    p_scan.add_argument("--port", type=int, default=8080, help="Server port")

    # Benchmark command
    p_bench = subparsers.add_parser("benchmark", help="Run benchmark suite")
    p_bench.add_argument("--iterations", type=int, default=10, help="Iterations per profile")
    p_bench.add_argument("--json", action="store_true", help="Output JSON results")

    # Test command
    subparsers.add_parser("test", help="Run unit test suite")

    # Serve command
    p_serve = subparsers.add_parser("serve", help="Host report directory")
    p_serve.add_argument("--dir", default="./web", help="Directory to serve")
    p_serve.add_argument("--port", type=int, default=8080, help="Port to bind server")
    p_serve.add_argument("--no-browser", action="store_true", help="Do not automatically open browser")

    # Default to demo if no command provided
    if len(sys.argv) == 1:
        parser.print_help()
        print("\n[*] Defaulting to Demo Mode:")
        class DefaultArgs:
            port = 8080
            no_browser = False
        cmd_demo(DefaultArgs())
        return

    args, unknown = parser.parse_known_args()

    if args.command == "demo":
        cmd_demo(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "benchmark":
        cmd_benchmark(args)
    elif args.command == "test":
        cmd_test(args)
    elif args.command == "serve":
        cmd_serve(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
