"""
Unit Tests for Advanced Research Features:
1. Attack Path Synthesis & Blast Radius Analysis
2. Ransomware Defense & System Resilience Engine
3. CISA Zero Trust Maturity Model (ZTMM v2.0) Device Pillar Evaluator
4. Empirical Comparative Evaluation Engine
"""
import unittest
from winsecure.models import Finding, FindingStatus, Severity
from winsecure.analytics.attack_path import AttackPathEngine
from winsecure.analytics.ransomware_resilience import RansomwareResilienceEngine
from winsecure.compliance.zero_trust import ZeroTrustEvaluator, ZeroTrustStage
from winsecure.comparison.evaluation import ComparativeEvaluationEngine


def _make_f(fid, status=FindingStatus.FAIL, severity=Severity.HIGH, category="General"):
    return Finding(
        id=fid,
        title=f"Finding {fid}",
        category=category,
        severity=severity,
        status=status,
        confidence=0.95,
        description="Test finding description",
        expected="Secure",
        actual="Insecure",
        impact="High impact",
        remediation="Harden setting",
    )


class TestAttackPathEngine(unittest.TestCase):
    def test_clean_findings_minimal_blast_radius(self):
        findings = [
            _make_f("WS-REG-001", status=FindingStatus.PASS),
            _make_f("WS-DEF-001", status=FindingStatus.PASS),
        ]
        res = AttackPathEngine.analyze(findings)
        self.assertEqual(res["detected_paths_count"], 0)
        self.assertEqual(res["blast_radius_score"], 0.0)
        self.assertEqual(res["blast_radius_level"], "MINIMAL (HARDENED)")
        self.assertEqual(len(res["choke_points"]), 0)

    def test_lsass_attack_path_synthesis(self):
        # Trigger AP-001: Group A (WS-REG-001) + Group B (WS-UAC-001)
        findings = [
            _make_f("WS-REG-001", status=FindingStatus.FAIL, severity=Severity.CRITICAL),
            _make_f("WS-UAC-001", status=FindingStatus.FAIL, severity=Severity.HIGH),
        ]
        res = AttackPathEngine.analyze(findings)
        self.assertGreaterEqual(res["detected_paths_count"], 1)
        self.assertGreater(res["blast_radius_score"], 0.0)
        path_ids = [p["id"] for p in res["attack_paths"]]
        self.assertIn("AP-001", path_ids)
        self.assertTrue(any(cp["control_id"] == "WS-REG-001" for cp in res["choke_points"]))

    def test_ransomware_attack_path_synthesis(self):
        # Trigger AP-003: Group A (WS-RSM-001) + Group B (WS-DEF-001)
        findings = [
            _make_f("WS-RSM-001", status=FindingStatus.FAIL, severity=Severity.CRITICAL),
            _make_f("WS-DEF-001", status=FindingStatus.FAIL, severity=Severity.CRITICAL),
        ]
        res = AttackPathEngine.analyze(findings)
        self.assertGreaterEqual(res["detected_paths_count"], 1)
        path_ids = [p["id"] for p in res["attack_paths"]]
        self.assertIn("AP-003", path_ids)


class TestRansomwareResilienceEngine(unittest.TestCase):
    def test_hardened_ransomware_posture(self):
        findings = [
            _make_f("WS-RSM-001", status=FindingStatus.PASS),
            _make_f("WS-RSM-002", status=FindingStatus.PASS),
            _make_f("WS-SMB-001", status=FindingStatus.PASS),
            _make_f("WS-SMB-002", status=FindingStatus.PASS),
            _make_f("WS-ENC-001", status=FindingStatus.PASS),
            _make_f("WS-AUD-001", status=FindingStatus.PASS),
            _make_f("WS-PS-001", status=FindingStatus.PASS),
        ]
        res = RansomwareResilienceEngine.evaluate(findings, {})
        self.assertGreaterEqual(res["ransomware_defense_index"], 85.0)
        self.assertIn("HARDENED", res["resilience_level"])
        self.assertEqual(len(res["recommendations"]), 0)

    def test_vulnerable_ransomware_posture(self):
        findings = [
            _make_f("WS-RSM-001", status=FindingStatus.FAIL),
            _make_f("WS-RSM-002", status=FindingStatus.FAIL),
            _make_f("WS-SMB-002", status=FindingStatus.FAIL),
            _make_f("WS-ENC-001", status=FindingStatus.FAIL),
        ]
        res = RansomwareResilienceEngine.evaluate(findings, {})
        self.assertLess(res["ransomware_defense_index"], 65.0)
        self.assertGreaterEqual(len(res["recommendations"]), 3)


class TestZeroTrustEvaluator(unittest.TestCase):
    def test_optimal_zero_trust_stage(self):
        all_zt_controls = [
            "WS-SYS-001", "WS-SYS-002", "WS-CET-001",
            "WS-VBS-001", "WS-APP-001", "WS-LOL-001", "WS-EXP-001",
            "WS-REG-001", "WS-REG-002", "WS-LAPS-001", "WS-CG-001",
            "WS-FW-001", "WS-FW-002", "WS-FW-004", "WS-SMB-002", "WS-NET-001",
            "WS-DEF-001", "WS-DEF-002", "WS-PS-001", "WS-AUD-001", "WS-SYS-003",
        ]
        findings = [_make_f(cid, status=FindingStatus.PASS) for cid in all_zt_controls]
        res = ZeroTrustEvaluator.evaluate(findings)
        self.assertIn(res["overall_stage"], (ZeroTrustStage.OPTIMAL.value, ZeroTrustStage.ADVANCED.value))
        self.assertGreaterEqual(res["overall_maturity_percent"], 80.0)
        self.assertEqual(len(res["dimensions"]), 5)

    def test_traditional_zero_trust_stage(self):
        all_zt_controls = [
            "WS-SYS-001", "WS-SYS-002", "WS-CET-001",
            "WS-VBS-001", "WS-APP-001", "WS-LOL-001", "WS-EXP-001",
            "WS-REG-001", "WS-REG-002", "WS-LAPS-001", "WS-CG-001",
        ]
        findings = [_make_f(cid, status=FindingStatus.FAIL) for cid in all_zt_controls]
        res = ZeroTrustEvaluator.evaluate(findings)
        self.assertIn(res["overall_stage"], (ZeroTrustStage.TRADITIONAL.value, ZeroTrustStage.INITIAL.value))
        self.assertGreater(res["gaps_count"], 0)


class TestComparativeEvaluationEngine(unittest.TestCase):
    def test_evolution_matrix(self):
        evo = ComparativeEvaluationEngine.get_version_evolution()
        self.assertGreaterEqual(len(evo), 8)
        features = [e["feature"] for e in evo]
        self.assertIn("Specialized Security Modules", features)
        self.assertIn("Attack Path Synthesis", features)
        self.assertIn("Ransomware Resilience Index (RDI)", features)

    def test_industry_benchmark(self):
        bench = ComparativeEvaluationEngine.get_industry_benchmark()
        self.assertEqual(len(bench), 8)
        tools = [b["tool"] for b in bench]
        self.assertTrue(any("WinSecure" in t for t in tools))
        self.assertTrue(any("Defender" in t for t in tools))

    def test_cli_formatting(self):
        output = ComparativeEvaluationEngine.format_cli_comparison()
        self.assertIn("WINSECURE PLATFORM", output)
        self.assertIn("AEGIS PRIME", output)
        self.assertIn("ShieldFS", output)
        self.assertIn("Bayesian Attack Graphs", output)


if __name__ == "__main__":
    unittest.main()
