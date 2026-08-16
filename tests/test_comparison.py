"""
Unit Tests for Tool Comparison Engine
"""
import unittest
from winsecure.comparison import ComparisonEngine, COMPARISON_PROFILES


class TestComparisonEngine(unittest.TestCase):
    def test_profile_count(self):
        self.assertGreaterEqual(len(COMPARISON_PROFILES), 8)

    def test_winsecure_profile(self):
        ws = next((p for p in COMPARISON_PROFILES if p.id == "winsecure"), None)
        self.assertIsNotNone(ws)
        self.assertIn("WinSecure", ws.name)
        self.assertEqual(ws.windows_domains_covered, 30)
        self.assertIn("CIS Win11 Enterprise 5.0.1", ws.compliance_mappings)

    def test_matrix_structure(self):
        matrix = ComparisonEngine.get_comparison_matrix()
        self.assertIn("dimensions", matrix)
        self.assertIn("tools", matrix)
        self.assertEqual(len(matrix["tools"]), len(COMPARISON_PROFILES))


if __name__ == "__main__":
    unittest.main()
