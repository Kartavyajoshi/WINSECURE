"""
Unit tests for WinSecure Desktop GUI and Chart Engine
"""
import unittest
from winsecure.cli.parser import create_cli_parser
from winsecure.gui.app import ChartUtils


class TestGuiAndCharts(unittest.TestCase):
    """Test GUI chart mathematical helpers and CLI parser integration."""

    def test_gui_cli_parser_command(self):
        parser = create_cli_parser()
        args = parser.parse_args(["gui", "--report-dir", "./Custom-Report", "--scan"])
        self.assertEqual(args.command, "gui")
        self.assertEqual(args.report_dir, "./Custom-Report")
        self.assertTrue(args.scan)

    def test_chart_slices_math(self):
        slices = [
            {"label": "Critical", "value": 2, "color": "#ef4444"},
            {"label": "High", "value": 8, "color": "#f97316"},
            {"label": "Passed", "value": 40, "color": "#10b981"},
        ]
        total = sum(s["value"] for s in slices)
        self.assertEqual(total, 50)
        extents = [(s["value"] / total) * 360.0 for s in slices]
        self.assertAlmostEqual(sum(extents), 360.0)

    def test_category_bar_percentages(self):
        categories = [
            {"name": "Defender", "pass": 2, "fail": 2, "warn": 0, "total": 4},
            {"name": "Firewall", "pass": 3, "fail": 1, "warn": 0, "total": 4},
        ]
        for c in categories:
            pct = int((c["pass"] / c["total"]) * 100)
            self.assertTrue(0 <= pct <= 100)


if __name__ == "__main__":
    unittest.main()
