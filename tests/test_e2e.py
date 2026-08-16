"""
End-to-End Integration and Report Generation Test
"""
import os
import tempfile
import unittest
from winsecure.cli.main import main


class TestEndToEndExecution(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cli_scan_with_report_generation(self):
        out_dir = os.path.join(self.temp_dir.name, "report_output")
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        fix_path = os.path.join(base_dir, "fixtures", "hardened.json")

        exit_code = main(["scan", "-o", out_dir, "--fixture", fix_path])
        self.assertEqual(exit_code, 0)

        # Verify generated files
        self.assertTrue(os.path.isfile(os.path.join(out_dir, "index.html")))
        self.assertTrue(os.path.isfile(os.path.join(out_dir, "Executive_Report.html")))
        self.assertTrue(os.path.isfile(os.path.join(out_dir, "Technical_Report.html")))
        self.assertTrue(os.path.isfile(os.path.join(out_dir, "findings.csv")))
        self.assertTrue(os.path.isfile(os.path.join(out_dir, "scan_result.json")))
        self.assertTrue(os.path.isfile(os.path.join(out_dir, "data", "findings.json")))
        self.assertTrue(os.path.isfile(os.path.join(out_dir, "data", "summary.json")))
        self.assertTrue(os.path.isfile(os.path.join(out_dir, "data", "compliance.json")))
        self.assertTrue(os.path.isfile(os.path.join(out_dir, "data", "inventory.json")))

        # Verify index.html is self-contained with inlined styles and scripts
        with open(os.path.join(out_dir, "index.html"), "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("<style>", content)
            self.assertIn("<script>", content)


if __name__ == "__main__":
    unittest.main()
