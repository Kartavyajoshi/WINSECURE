#!/usr/bin/env python3
"""
Self-Validation & Integrity Verifier
"""
import os
import sys
import unittest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from winsecure.rules import RuleLoader
from winsecure.compliance import ComplianceEngine
from winsecure.scanners import ALL_SCANNERS
from winsecure.comparison import ComparisonEngine

if __name__ == "__main__":
    print("[*] Verifying WinSecure Platform Integrity...")
    
    # 1. Verify Rules
    rules = RuleLoader.load_builtin_rules()
    print(f"  [OK] Loaded {len(rules)} built-in security rules")
    assert len(rules) >= 50, f"Expected at least 50 rules, got {len(rules)}"

    # 2. Verify Scanners
    print(f"  [OK] Registered {len(ALL_SCANNERS)} scanner modules")
    assert len(ALL_SCANNERS) == 32, f"Expected exactly 32 scanner modules, got {len(ALL_SCANNERS)}"

    # 3. Verify Compliance Frameworks
    engine = ComplianceEngine()
    print(f"  [OK] Loaded {len(engine.controls)} compliance framework benchmarks")
    assert len(engine.controls) >= 4, "Expected at least 4 compliance benchmarks"

    # 4. Verify Comparison Engine
    matrix = ComparisonEngine.get_comparison_matrix()
    print(f"  [OK] Loaded comparison matrix for {len(matrix['tools'])} tools across {len(matrix['dimensions'])} dimensions")
    assert len(matrix['tools']) >= 8, "Expected at least 8 tool comparison profiles"

    # 5. Run full test suite
    tests_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests")
    loader = unittest.TestLoader()
    suite = loader.discover(tests_dir)
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    
    if result.wasSuccessful():
        print("\n[+] All integrity validations PASSED successfully!")
        sys.exit(0)
    else:
        print("\n[-] Integrity validation FAILED!")
        sys.exit(1)
