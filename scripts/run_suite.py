#!/usr/bin/env python3
"""
WinSecure Full Verification Suite
One command that runs every verification stage:
  1. Unit & integration test suite (fresh interpreter)
  2. Platform integrity validation (rules, scanners, compliance benchmarks)
  3. Offline end-to-end fixture scan with artifact verification
  4. Plugin registry check (loads cleanly, zero errors)
  5. Benchmark pass (optional, --benchmark)
"""
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

PASS = "PASS"
FAIL = "FAIL"


# ----------------------------------------------------------------------
# Stage implementations — each returns (ok: bool, detail: str)
# ----------------------------------------------------------------------

def step_tests():
    """Runs the full unit & integration test suite in a fresh interpreter."""
    res = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "tests"],
        cwd=ROOT,
    )
    if res.returncode != 0:
        return False, f"test runner exited with code {res.returncode}"
    return True, "all tests passed"


def step_integrity():
    """Verifies rule catalogs, scanner registration, and compliance benchmarks."""
    from winsecure.rules import RuleLoader
    from winsecure.compliance import ComplianceEngine
    from winsecure.scanners import ALL_SCANNERS

    rules = RuleLoader.load_builtin_rules()
    if len(rules) < 55:
        return False, f"only {len(rules)} rules loaded (expected >= 55)"

    if len(ALL_SCANNERS) != 36:
        return False, f"{len(ALL_SCANNERS)} scanners registered (expected 36)"

    engine = ComplianceEngine()
    if len(engine.controls) < 4:
        return False, f"only {len(engine.controls)} compliance benchmarks (expected >= 4)"

    return True, f"{len(rules)} rules, {len(ALL_SCANNERS)} scanners, {len(engine.controls)} benchmarks"


def step_fixture_scan():
    """Offline end-to-end scan smoke test with generated-artifact verification."""
    fixture = os.path.join(ROOT, "fixtures", "standard_enterprise.json")
    if not os.path.exists(fixture):
        return False, f"fixture not found: {fixture}"

    from winsecure.cli.main import main as cli_main

    with tempfile.TemporaryDirectory(prefix="ws_suite_") as tmp:
        code = cli_main([
            "scan",
            "--fixture", fixture,
            "--output", tmp,
            "--emit-scripts",
            "--no-log",
        ])
        if code != 0:
            return False, f"scan exited with code {code}"

        required = [
            "index.html",
            "scan_result.json",
            os.path.join("siem", "findings_splunk.ndjson"),
            os.path.join("remediation_scripts", "run_all_remediations.ps1"),
        ]
        missing = [r for r in required if not os.path.exists(os.path.join(tmp, r))]
        if missing:
            return False, f"missing artifacts: {', '.join(missing)}"

    return True, "scan pipeline + all artifacts verified"


def step_plugins():
    """Validates the plugin registry loads with zero errors."""
    from winsecure.plugins.loader import PluginRegistry

    registry = PluginRegistry()
    registry.discover([os.path.join(ROOT, "plugins")])
    if registry.load_errors:
        first = registry.load_errors[0]
        return False, (
            f"{len(registry.load_errors)} load error(s), first: "
            f"{first.get('plugin')}: {first.get('error')}"
        )
    return True, f"{len(registry.plugins)} plugin(s) loaded cleanly"


def step_benchmark():
    """Runs a short synthetic benchmark pass."""
    from winsecure.cli.main import main as cli_main

    code = cli_main(["benchmark", "--iterations", "2"])
    if code != 0:
        return False, f"benchmark exited with code {code}"
    return True, "2-iteration benchmark completed"


# ----------------------------------------------------------------------
# Orchestrator
# ----------------------------------------------------------------------

def run_suite(include_tests: bool = True, include_benchmark: bool = False) -> int:
    """Executes every enabled stage and prints a summary; returns exit code."""
    steps = []
    if include_tests:
        steps.append(("Unit & Integration Tests", step_tests))
    steps.append(("Platform Integrity", step_integrity))
    steps.append(("Offline Fixture Scan (E2E)", step_fixture_scan))
    steps.append(("Plugin Registry", step_plugins))
    if include_benchmark:
        steps.append(("Benchmark (2 iterations)", step_benchmark))

    print("=" * 62)
    print(" WinSecure Full Verification Suite")
    print("=" * 62)

    results = []
    suite_start = time.time()
    for name, fn in steps:
        print(f"\n>>> {name}")
        print("-" * 62)
        start = time.time()
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        elapsed = time.time() - start
        results.append((name, ok, detail, elapsed))
        print(f"[{PASS if ok else FAIL}] {detail} ({elapsed:.1f}s)")

    total = time.time() - suite_start
    passed = sum(1 for r in results if r[1])

    print("\n" + "=" * 62)
    print(" SUITE SUMMARY")
    print("=" * 62)
    for name, ok, _detail, elapsed in results:
        print(f"  [{PASS if ok else FAIL}] {name:<32} {elapsed:6.1f}s")
    failed = len(results) - passed
    print(f"\n  {passed}/{len(results)} stages passed in {total:.1f}s")
    print("=" * 62)
    return 0 if failed == 0 else 1


def main():
    include_tests = "--skip-tests" not in sys.argv
    include_benchmark = "--benchmark" in sys.argv
    sys.exit(run_suite(include_tests=include_tests, include_benchmark=include_benchmark))


if __name__ == "__main__":
    main()
