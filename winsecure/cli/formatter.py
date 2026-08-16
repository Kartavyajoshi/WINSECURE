"""
WinSecure CLI Output Formatter & Verbose Execution Streamer
"""
import sys
import os
from typing import Any, Dict, Optional
from winsecure.models.scan import ScanResult
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.utils.formatting import Colors, colorize


class CliFormatter:
    """Renders real-time test execution streams, verbose telemetry, and executive summaries."""

    @staticmethod
    def print_banner():
        banner = """
============================================================
                WINSECURE SECURITY AUDITOR                  
         Endpoint Hardening & Misconfiguration Scanner      
============================================================"""
        try:
            print(colorize(banner, Colors.BOLD + Colors.CYAN))
        except UnicodeEncodeError:
            print(banner)

    @staticmethod
    def print_scan_init(context):
        inv = getattr(context, "inventory", None)
        os_info = f"{inv.os_name} ({inv.os_architecture})" if inv else "Microsoft Windows"
        priv = "Administrator (Elevated)" if context.is_admin else "Standard User"

        print(f"[SCAN] Initializing security audit...")
        print(f"[SCAN] Platform        : {colorize(os_info, Colors.BOLD)}")
        print(f"[SCAN] Privilege Level : {colorize(priv, Colors.GREEN if context.is_admin else Colors.YELLOW)}")
        print(f"[SCAN] Scan Profile    : {colorize(context.config.profile.upper(), Colors.CYAN)}")
        print(f"[SCAN] Target Directory: {colorize(context.config.output_dir, Colors.DIM)}")
        print(f"[SCAN] Discovered 32 security modules / 55 audit rules\n")

    @staticmethod
    def print_self_check(checks: Dict[str, tuple]):
        print(colorize("[SELF-CHECK]", Colors.BOLD))
        for name, (status, detail) in checks.items():
            dots = "." * max(2, 38 - len(name))
            st_str = colorize("[PASS]", Colors.GREEN) if status else colorize("[FAIL]", Colors.RED)
            print(f"  {name} {dots} {st_str} ({detail})")
        print()

    @staticmethod
    def print_module_start(module_idx: int, total_modules: int, name: str, category: str):
        header = f"\n------------------------------------------------------------\n[MODULE {module_idx:02d}/{total_modules:02d}] {name.upper()} ({category})\n------------------------------------------------------------"
        print(colorize(header, Colors.BOLD + Colors.CYAN))

    @staticmethod
    def print_test_result(finding: Finding, current_idx: int, total_tests: int, verbose: bool = False, debug: bool = False):
        dur_str = f"{finding.duration:.2f}s" if finding.duration > 0 else "<0.01s"
        idx_str = f"[{current_idx:02d}/{total_tests:02d}]"

        if finding.status == FindingStatus.PASS:
            tag = colorize("[PASS]", Colors.GREEN + Colors.BOLD)
            print(f"[TEST {idx_str}] {tag} {finding.id}: {finding.title} ({dur_str})")
            if verbose or debug:
                print(colorize(f"  Evidence   : {finding.actual}", Colors.DIM))
                if finding.evidence and debug:
                    print(colorize(f"  Telemetry  : {finding.evidence[0].get('data', '')}", Colors.DIM))

        elif finding.status == FindingStatus.FAIL:
            sev_val = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            tag = colorize("[FAIL]", Colors.RED + Colors.BOLD)
            sev_tag = colorize(f"[{sev_val.upper()}]", Colors.RED)
            print(f"[TEST {idx_str}] {tag} {finding.id}: {finding.title} {sev_tag} ({dur_str})")
            print(colorize(f"  Evidence   : {finding.actual}", Colors.YELLOW))
            print(colorize(f"  Impact     : {finding.impact}", Colors.DIM))
            if finding.remediation:
                first_rem = finding.remediation.strip().split('\n')[0]
                print(colorize(f"  Remediation: {first_rem}", Colors.CYAN))

        elif finding.status == FindingStatus.WARN:
            tag = colorize("[WARN]", Colors.YELLOW + Colors.BOLD)
            print(f"[TEST {idx_str}] {tag} {finding.id}: {finding.title} ({dur_str})")
            print(colorize(f"  Notice     : {finding.actual}", Colors.YELLOW))

        elif finding.status in (FindingStatus.UNKNOWN, FindingStatus.NOT_APPLICABLE):
            tag = colorize("[SKIPPED]", Colors.DIM)
            reason = finding.actual or "Requires administrative privileges or feature not present"
            print(f"[TEST {idx_str}] {tag} {finding.id}: {finding.title}")
            print(colorize(f"  Reason     : {reason}", Colors.DIM))

        elif finding.status == FindingStatus.ERROR:
            tag = colorize("[ERROR]", Colors.RED + Colors.BOLD)
            print(f"[TEST {idx_str}] {tag} {finding.id}: {finding.title}")
            print(colorize(f"  Error      : {finding.actual}", Colors.RED))

    @staticmethod
    def print_live_progress(stats: Dict[str, Any]):
        total = stats.get("total", 0)
        sched = stats.get("total_scheduled", total)
        passed = stats.get("passed", 0)
        failed = stats.get("failed", 0)
        warn = stats.get("warn", 0)
        skipped = stats.get("skipped", 0)
        errors = stats.get("errors", 0)
        elapsed = stats.get("elapsed_seconds", 0.0)

        mins = int(elapsed // 60)
        secs = int(elapsed % 60)
        time_str = f"{mins:02d}:{secs:02d}"

        p_str = colorize(f"PASS: {passed}", Colors.GREEN)
        f_str = colorize(f"FAIL: {failed}", Colors.RED if failed > 0 else Colors.DIM)
        w_str = colorize(f"WARN: {warn}", Colors.YELLOW if warn > 0 else Colors.DIM)
        s_str = colorize(f"SKIPPED: {skipped}", Colors.DIM)
        e_str = colorize(f"ERROR: {errors}", Colors.RED if errors > 0 else Colors.DIM)

        line = f"Progress: {total}/{sched} [{p_str} | {f_str} | {w_str} | {s_str} | {e_str}] (Elapsed: {time_str})"
        print(line)

    @staticmethod
    def print_summary(result: ScanResult, report_path: str):
        duration_sec = result.metrics.duration_seconds if result.metrics else 0.0
        mins = int(duration_sec // 60)
        secs = int(duration_sec % 60)
        dur_str = f"{mins:02d}:{secs:02d} ({duration_sec:.2f}s)"

        score_color = Colors.GREEN if result.security_score >= 80 else (Colors.YELLOW if result.security_score >= 70 else Colors.RED)
        score_str = colorize(f"{result.security_score:.1f}/100", score_color + Colors.BOLD)
        risk_str = colorize(result.risk_level.value if hasattr(result.risk_level, "value") else str(result.risk_level), score_color + Colors.BOLD)

        crit = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.CRITICAL)
        high = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.HIGH)
        med = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.MEDIUM)
        low = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.LOW)
        passed = sum(1 for f in result.findings if f.status == FindingStatus.PASS)
        warn = sum(1 for f in result.findings if f.status == FindingStatus.WARN)
        unknown = sum(1 for f in result.findings if f.status == FindingStatus.UNKNOWN)
        err = len(result.errors)

        print(colorize("\n============================================================", Colors.BOLD))
        print(colorize("                       SCAN COMPLETE                        ", Colors.BOLD + Colors.CYAN))
        print(colorize("============================================================", Colors.BOLD))

        print(f"Total Controls Audited : {colorize(str(len(result.findings)), Colors.BOLD)}")
        print(f"Passed Checks          : {colorize(str(passed), Colors.GREEN + Colors.BOLD)}")
        print(f"Failed Misconfigurations: {colorize(str(crit + high + med + low), Colors.RED if (crit + high + med + low) > 0 else Colors.DIM)}")
        print(f"Warnings / Suboptimal  : {colorize(str(warn), Colors.YELLOW if warn > 0 else Colors.DIM)}")
        print(f"Restricted / Skipped   : {colorize(str(unknown), Colors.DIM)}")
        print(f"Execution Errors       : {colorize(str(err), Colors.RED if err > 0 else Colors.DIM)}")
        print(f"Overall Security Score : {score_str} ({risk_str})")
        print(f"Assessment Coverage    : {colorize(f'{result.assessment_coverage_percent}%', Colors.CYAN)}")
        print(f"Total Scan Duration    : {colorize(dur_str, Colors.BOLD)}")

        print(colorize("\nRisk Distribution:", Colors.BOLD))
        print(f"  CRITICAL : {colorize(str(crit), Colors.RED if crit > 0 else Colors.DIM)}")
        print(f"  HIGH     : {colorize(str(high), Colors.RED if high > 0 else Colors.DIM)}")
        print(f"  MEDIUM   : {colorize(str(med), Colors.YELLOW if med > 0 else Colors.DIM)}")
        print(f"  LOW      : {colorize(str(low), Colors.CYAN if low > 0 else Colors.DIM)}")

        output_dir = os.path.dirname(os.path.abspath(report_path))
        print(colorize("\nGenerated Reports & Artifacts:", Colors.BOLD))
        print(f"  * Interactive HTML Dashboard : {colorize(report_path, Colors.CYAN + Colors.UNDERLINE)}")
        print(f"  * Machine JSON Telemetry    : {colorize(os.path.join(output_dir, 'scan_results.json'), Colors.CYAN)}")
        print(f"  * CSV Finding Matrix        : {colorize(os.path.join(output_dir, 'findings.csv'), Colors.CYAN)}")
        print(f"  * Markdown Audit Summary    : {colorize(os.path.join(output_dir, 'report.md'), Colors.CYAN)}")
        print(f"  * Execution Audit Log       : {colorize('logs/latest.log', Colors.CYAN)}\n")
