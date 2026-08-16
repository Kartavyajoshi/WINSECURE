"""
WinSecure Central Scan Execution Pipeline
"""
import time
from typing import Callable, Optional, List
from winsecure.core.context import ScanContext
from winsecure.core.environment import EnvironmentValidator
from winsecure.collectors import (
    RegistryCollector,
    PowerShellCollector,
    DefenderCollector,
    FirewallCollector,
    AccountsCollector,
    ServicesCollector,
    AuditCollector,
    BitLockerCollector,
    NetworkCollector,
    SoftwareCollector,
    TasksCollector,
    UpdatesCollector,
    EventLogCollector,
    WmiCollector,
    FixtureCollector,
)
from winsecure.scanners import ALL_SCANNERS
from winsecure.inventory import InventoryBuilder
from winsecure.compliance import ComplianceEngine
from winsecure.scoring import RiskEngine, AnomalyEngine
from winsecure.analytics import ExecutiveAnalytics
from winsecure.remediation import RemediationEngine
from winsecure.comparison import ComparisonEngine
from winsecure.benchmarking import MetricsCollector, ScanComparison
from winsecure.models.scan import ScanResult
from winsecure.models.finding import Finding, FindingStatus
from winsecure.models.module import ScannerHealth
from winsecure.storage import DatabaseManager, ScanRepository
from winsecure.engine.validator import ScanValidator


class ScanPipeline:
    """Orchestrates the complete 8-step security assessment pipeline."""

    def __init__(self, context: ScanContext):
        self.context = context
        self.metrics_collector = MetricsCollector()

    def run(self, progress_callback: Optional[Callable[[int, int, str], None]] = None) -> ScanResult:
        total_steps = 8

        def notify(step_idx: int, desc: str):
            if progress_callback:
                progress_callback(step_idx, total_steps, desc)

        # [1/8] Environment discovery
        notify(1, "Environment discovery")
        valid, msg = EnvironmentValidator.validate(self.context)
        if not valid:
            self.context.add_error("EnvironmentValidator", msg)

        # [2/8] Security collection
        notify(2, "Security collection")
        if self.context.config.fixture_path:
            fc = FixtureCollector(self.context, self.context.config.fixture_path)
            fc.collect()
        else:
            collectors = [
                WmiCollector(self.context),
                RegistryCollector(self.context),
                PowerShellCollector(self.context),
                DefenderCollector(self.context),
                FirewallCollector(self.context),
                AccountsCollector(self.context),
                ServicesCollector(self.context),
                AuditCollector(self.context),
                BitLockerCollector(self.context),
                NetworkCollector(self.context),
                SoftwareCollector(self.context),
                TasksCollector(self.context),
                UpdatesCollector(self.context),
                EventLogCollector(self.context),
            ]
            for c in collectors:
                try:
                    data = c.collect()
                    key = c.category.lower()
                    if key not in self.context.collected_artifacts:
                        self.context.collected_artifacts[key] = data
                except Exception as e:
                    self.context.add_error(c.name, str(e))

        # Build inventory
        self.context.inventory = InventoryBuilder.build(self.context)

        # [3/8] Configuration assessment & Scanner execution (32 Modules)
        notify(3, "Configuration assessment")
        all_findings: List[Finding] = []
        scanner_health_list: List[ScannerHealth] = []

        for scanner_cls in ALL_SCANNERS:
            s_name = scanner_cls.__name__
            t_start = time.perf_counter()
            s_health = ScannerHealth(
                scanner_id=s_name,
                name=s_name,
                category="General",
                status="RUNNING",
            )

            try:
                scanner_instance = scanner_cls(self.context)
                meta = getattr(scanner_instance, "metadata", None)
                if meta:
                    s_health.scanner_id = meta.id
                    s_health.name = meta.name
                    s_health.category = meta.category
                    s_health.requires_admin = meta.requires_admin

                # Check elevation restriction
                if meta and meta.requires_admin and not self.context.is_admin and not self.context.config.fixture_path:
                    # Execute accessible parts or mark as UNKNOWN/requires_admin
                    scanner_findings = scanner_instance.run()
                    # If any findings returned as UNKNOWN due to permissions, record them
                    for f in scanner_findings:
                        if f.requires_admin and f.status == FindingStatus.UNKNOWN:
                            f.actual = "Requires administrative privileges"
                else:
                    scanner_findings = scanner_instance.run()

                elapsed_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
                s_health.execution_time_ms = elapsed_ms
                s_health.checks_count = len(scanner_findings)
                s_health.passed_count = sum(1 for f in scanner_findings if f.status == FindingStatus.PASS)
                s_health.failed_count = sum(1 for f in scanner_findings if f.status == FindingStatus.FAIL)
                s_health.warn_count = sum(1 for f in scanner_findings if f.status == FindingStatus.WARN)
                s_health.unknown_count = sum(1 for f in scanner_findings if f.status == FindingStatus.UNKNOWN)
                s_health.na_count = sum(1 for f in scanner_findings if f.status == FindingStatus.NOT_APPLICABLE)
                s_health.error_count = sum(1 for f in scanner_findings if f.status == FindingStatus.ERROR)
                
                evaluable = s_health.checks_count - s_health.unknown_count - s_health.error_count
                s_health.coverage_percent = round((evaluable / max(1, s_health.checks_count)) * 100.0, 1)
                s_health.status = "COMPLETED"

                all_findings.extend(scanner_findings)
            except Exception as e:
                elapsed_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
                s_health.execution_time_ms = elapsed_ms
                s_health.status = "FAILED"
                s_health.error_count = 1
                s_health.errors.append(str(e))
                self.context.add_error(s_name, str(e))

            scanner_health_list.append(s_health)

        self.context.findings = all_findings

        # [4/8] Threat-exposure & Compliance assessment
        notify(4, "Threat-exposure analysis")
        self.context.anomalies = AnomalyEngine.detect_anomalies(self.context.findings)

        notify(5, "Compliance assessment")
        comp_engine = ComplianceEngine()
        self.context.compliance_summaries = comp_engine.evaluate(self.context.findings)

        # [6/8] Risk calculation & Prioritized Remediation
        notify(6, "Risk calculation")
        score, risk_lvl, deductions = RiskEngine.calculate_score(self.context.findings)
        self.context.security_score = score
        self.context.risk_level = risk_lvl
        self.context.score_deductions = deductions

        self.context.remediations = RemediationEngine.generate_remediations(self.context.findings)
        self.context.executive_summary = ExecutiveAnalytics.generate_executive_summary(
            score, risk_lvl, self.context.findings, self.context.anomalies
        )
        self.context.ai_insights = {
            "themes": ExecutiveAnalytics.generate_themes(self.context.findings),
            "summary": self.context.executive_summary,
        }

        # Calculate Coverage Metrics
        total_checks = len(self.context.findings)
        unknown_checks = sum(1 for f in self.context.findings if f.status == FindingStatus.UNKNOWN)
        error_checks = sum(1 for f in self.context.findings if f.status == FindingStatus.ERROR)
        accessible_checks = total_checks - unknown_checks - error_checks
        restricted_checks = unknown_checks + error_checks
        coverage_pct = round((accessible_checks / max(1, total_checks)) * 100.0, 1)

        # [7/8] Benchmarking & Historical Drift Comparison
        passed = sum(1 for f in self.context.findings if f.status == FindingStatus.PASS)
        failed = sum(1 for f in self.context.findings if f.status == FindingStatus.FAIL)
        warn = sum(1 for f in self.context.findings if f.status == FindingStatus.WARN)
        na = sum(1 for f in self.context.findings if f.status == FindingStatus.NOT_APPLICABLE)
        err_count = len(self.context.errors)

        self.context.metrics = self.metrics_collector.finalize(
            total_checks=total_checks,
            passed=passed,
            failed=failed,
            warn=warn,
            unknown=unknown_checks,
            na=na,
            errors=err_count,
            privilege_coverage=self.context.privilege_coverage_percent,
        )
        self.context.metrics.assessment_coverage_percent = coverage_pct
        self.context.metrics.accessible_checks_count = accessible_checks
        self.context.metrics.restricted_checks_count = restricted_checks

        comparison_matrix = ComparisonEngine.get_comparison_matrix()

        # Check for previous scan in database to calculate drift
        drift_data = {}
        try:
            db_mgr = DatabaseManager(self.context.config.db_path)
            repo = ScanRepository(db_mgr)
            prev_scans = repo.get_latest_scans(limit=2)
            prev_scan = prev_scans[0] if prev_scans else None
            curr_dict = {
                "security_score": self.context.security_score,
                "findings": [f.to_dict() for f in self.context.findings]
            }
            drift_data = ScanComparison.compare_scans(curr_dict, prev_scan)
        except Exception:
            drift_data = {"has_previous": False, "score_delta": 0.0, "message": "Initial scan — baseline established."}

        # [7/8] Report generation (Deferred to Reporting Engine)
        notify(7, "Report generation")

        # [8/8] Validation & Integrity
        notify(8, "Validation")
        scan_result = ScanResult(
            scan_id=self.context.scan_id,
            timestamp=self.context.start_time_iso,
            winsecure_version="2.5.0",
            profile=self.context.config.profile,
            is_admin=self.context.is_admin,
            security_score=self.context.security_score,
            risk_level=self.context.risk_level,
            assessment_coverage_percent=coverage_pct,
            accessible_checks_count=accessible_checks,
            restricted_checks_count=restricted_checks,
            score_deductions=self.context.score_deductions,
            metrics=self.context.metrics,
            inventory=self.context.inventory,
            findings=self.context.findings,
            scanner_health=scanner_health_list,
            compliance_summaries=self.context.compliance_summaries,
            remediations=self.context.remediations,
            anomalies=self.context.anomalies,
            ai_insights=self.context.ai_insights,
            comparison_data=comparison_matrix,
            drift_data=drift_data,
            executive_summary=self.context.executive_summary,
            errors=self.context.errors,
        )

        # Validate result
        ScanValidator.validate_scan_result(scan_result)

        # Persist to SQLite
        try:
            db_mgr = DatabaseManager(self.context.config.db_path)
            repo = ScanRepository(db_mgr)
            repo.save_scan_result(scan_result)
        except Exception as e:
            self.context.add_error("DatabasePersistence", str(e))

        return scan_result
