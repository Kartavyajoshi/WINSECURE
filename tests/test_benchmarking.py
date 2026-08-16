"""
Unit Tests for Metrics Collector and Benchmark Suite
"""
import unittest
from winsecure.benchmarking import MetricsCollector, ScanComparison, BenchmarkSuite


class TestBenchmarkingSubsystem(unittest.TestCase):
    def test_metrics_collection(self):
        mc = MetricsCollector()
        metrics = mc.finalize(total_checks=50, passed=40, failed=8, warn=2, unknown=0, na=0, errors=0)
        self.assertEqual(metrics.total_checks, 50)
        self.assertEqual(metrics.passed_checks, 40)
        self.assertGreater(metrics.checks_per_second, 0.0)

    def test_scan_comparison(self):
        curr = {
            "security_score": 85.0,
            "findings": [{"id": "WS-DEF-001", "status": "PASS"}, {"id": "WS-FW-001", "status": "FAIL"}]
        }
        prev = {
            "scan_id": "SCAN-001",
            "timestamp": "2026-08-15T10:00:00Z",
            "security_score": 70.0,
            "findings": [{"id": "WS-DEF-001", "status": "FAIL"}, {"id": "WS-FW-001", "status": "FAIL"}]
        }
        delta = ScanComparison.compare_scans(curr, prev)
        self.assertTrue(delta["has_previous"])
        self.assertEqual(delta["score_delta"], 15.0)
        self.assertEqual(delta["fixed_findings_count"], 1)
        self.assertIn("WS-DEF-001", delta["fixed_findings"])

    def test_benchmark_suite_execution(self):
        res = BenchmarkSuite.run_benchmark(iterations=2)
        self.assertIn("overall_throughput_checks_per_sec", res)
        self.assertIn("profile_benchmarks", res)
        self.assertGreater(len(res["profile_benchmarks"]), 2)
        self.assertGreater(res["total_modules_benchmarked"], 25)


if __name__ == "__main__":
    unittest.main()
