"""
Unit Tests for WinSecure CLI Parser and Commands
"""
import io
import sys
import unittest
from winsecure.cli.parser import create_cli_parser
from winsecure.cli.main import main
from winsecure.version import __version__


class TestCli(unittest.TestCase):
    def setUp(self):
        self.parser = create_cli_parser()

    def test_version_command(self):
        saved_stdout = sys.stdout
        try:
            out = io.StringIO()
            sys.stdout = out
            code = main(["version"])
            self.assertEqual(code, 0)
            self.assertIn(__version__, out.getvalue())
        finally:
            sys.stdout = saved_stdout

    def test_help_command(self):
        saved_stdout = sys.stdout
        try:
            out = io.StringIO()
            sys.stdout = out
            code = main(["help"])
            self.assertEqual(code, 0)
            self.assertIn("scan", out.getvalue())
        finally:
            sys.stdout = saved_stdout

    def test_parser_options(self):
        args = self.parser.parse_args(["scan", "-o", "./custom_out", "-p", "hardened", "--no-color", "--serve", "--port", "9090"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.output, "./custom_out")
        self.assertEqual(args.profile, "hardened")
        self.assertTrue(args.no_color)
        self.assertTrue(args.serve)
        self.assertEqual(args.port, 9090)

    def test_serve_parser(self):
        args = self.parser.parse_args(["serve", "-d", "./custom_dir", "-p", "8888", "--no-browser"])
        self.assertEqual(args.command, "serve")
        self.assertEqual(args.dir, "./custom_dir")
        self.assertEqual(args.port, 8888)
        self.assertTrue(args.no_browser)


if __name__ == "__main__":
    unittest.main()
