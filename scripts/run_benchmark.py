#!/usr/bin/env python3
"""
Performance & Benchmark Execution Script
"""
import os
import sys
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from winsecure.core.config import ScanConfig
from winsecure.core.context import ScanContext
from winsecure.engine.pipeline import ScanPipeline

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    fix_path = os.path.join(base_dir, "fixtures", "hardened.json")
    
    config = ScanConfig(output_dir="/tmp/ws_bench_out", fixture_path=fix_path)
    ctx = ScanContext(config=config)
    pipeline = ScanPipeline(ctx)

    t0 = time.perf_counter()
    result = pipeline.run()
    elapsed = time.perf_counter() - t0

    print("========================================")
    print(" WinSecure Performance Benchmark Result ")
    print("========================================")
    print(f"Total Checks:       {len(result.findings)}")
    print(f"Scan Duration:      {elapsed:.4f} seconds")
    print(f"Throughput:         {len(result.findings) / max(0.0001, elapsed):.1f} checks/sec")
    print(f"Security Score:     {result.security_score}/100")
    print(f"Errors Encountered: {len(result.errors)}")
    print("========================================")
