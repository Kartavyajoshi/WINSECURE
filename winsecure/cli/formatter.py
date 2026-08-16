"""
WinSecure CLI Output Formatter
"""
import sys
from winsecure.models.scan import ScanResult
from winsecure.models.finding import FindingStatus, Severity
from winsecure.utils.formatting import Colors, colorize, format_score_bar


class CliFormatter:
    """Renders clean, professional executive CLI banners and step summaries."""

    @staticmethod
    def print_banner():
        # Use clean, universal border characters to ensure 100% compatibility across all Windows shells
        banner = """
======================================================
               WinSecure Security Platform            
                    Full System Scan                  
======================================================"""
        try:
            print(colorize(banner, Colors.BOLD + Colors.CYAN))
        except UnicodeEncodeError:
            print(banner)

    @staticmethod
    def print_step(step_idx: int, total_steps: int, description: str, status: str = "[OK]"):
        status_str = colorize(status, Colors.GREEN if "OK" in status or status == "✓" else Colors.YELLOW)
        line = f"[{step_idx}/{total_steps}] {description.ljust(34)} {status_str}"
        try:
            print(line)
        except UnicodeEncodeError:
            print(f"[{step_idx}/{total_steps}] {description.ljust(34)} {status}")

    @staticmethod
    def print_summary(result: ScanResult, report_path: str):
        print()
        score_color = Colors.GREEN if result.security_score >= 80 else (Colors.YELLOW if result.security_score >= 70 else Colors.RED)
        score_str = colorize(f"{result.security_score}/100", score_color + Colors.BOLD)
        cov_str = colorize(f"{result.assessment_coverage_percent}%", Colors.CYAN + Colors.BOLD)

        avg_comp = 100.0
        if result.compliance_summaries:
            avg_comp = round(sum(c.compliance_percentage for c in result.compliance_summaries) / len(result.compliance_summaries), 1)
        comp_str = colorize(f"{avg_comp}%", Colors.BOLD)

        print(f"Security Score       {score_str}")
        print(f"Coverage             {cov_str}")
        print(f"Compliance           {comp_str}")
        print(f"Risk Level           {colorize(result.risk_level.value, score_color)}")

        crit = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.CRITICAL)
        high = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.HIGH)
        med = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.MEDIUM)
        low = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.LOW)
        warn = sum(1 for f in result.findings if f.status == FindingStatus.WARN)
        unknown = sum(1 for f in result.findings if f.status == FindingStatus.UNKNOWN)
        err = len(result.errors)

        print()
        print(f"Critical             {colorize(str(crit), Colors.RED if crit > 0 else Colors.DIM)}")
        print(f"High                 {colorize(str(high), Colors.RED if high > 0 else Colors.DIM)}")
        print(f"Medium               {colorize(str(med), Colors.YELLOW if med > 0 else Colors.DIM)}")
        print(f"Low                  {colorize(str(low), Colors.CYAN if low > 0 else Colors.DIM)}")
        print(f"Warnings             {colorize(str(warn), Colors.YELLOW if warn > 0 else Colors.DIM)}")
        print(f"Unknown              {colorize(str(unknown), Colors.DIM)}")
        print(f"Errors               {colorize(str(err), Colors.RED if err > 0 else Colors.DIM)}")

        # Print Error Summary if any non-fatal errors occurred (Section 44)
        if result.errors:
            print(colorize(f"\nScan completed with {len(result.errors)} non-fatal error(s):", Colors.YELLOW))
            for e in result.errors[:3]:
                print(f"  * Module: {colorize(e.get('module', 'N/A'), Colors.BOLD)}")
                print(f"    Reason: {e.get('error', 'Unknown error')}")

        print(colorize("\nReport:", Colors.BOLD))
        print(f"  {colorize(report_path, Colors.CYAN + Colors.UNDERLINE)}\n")
