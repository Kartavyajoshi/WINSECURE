"""
WinSecure Central Result Collector & Event Aggregator
"""
import time
from typing import Any, Callable, Dict, List, Optional
from winsecure.models.finding import Finding, FindingStatus, Severity


class ResultCollector:
    """Central aggregator and event dispatcher for all security test results."""

    def __init__(self):
        self.findings: List[Finding] = []
        self.errors: List[Dict[str, Any]] = []
        self.listeners: Dict[str, List[Callable[..., None]]] = {}
        self.start_time: float = time.time()
        self.total_scheduled: int = 0

    def subscribe(self, event_type: str, callback: Callable[..., None]) -> None:
        """Subscribes a listener to a specific scan lifecycle event."""
        if event_type not in self.listeners:
            self.listeners[event_type] = []
        self.listeners[event_type].append(callback)

    def emit(self, event_type: str, *args, **kwargs) -> None:
        """Emits an event to all registered subscribers."""
        for cb in self.listeners.get(event_type, []):
            try:
                cb(*args, **kwargs)
            except Exception:
                pass

    def add_finding(self, finding: Finding) -> None:
        """Records a normalized finding and dispatches a test_completed event."""
        self.findings.append(finding)
        self.emit("test_completed", finding, self.get_stats())

    def add_error(self, module: str, message: str, exc: Optional[Exception] = None) -> None:
        """Records an execution error and dispatches a test_error event."""
        err_entry = {
            "module": module,
            "error": str(message),
            "timestamp": time.time(),
        }
        self.errors.append(err_entry)
        self.emit("test_error", module, message, self.get_stats())

    def get_stats(self) -> Dict[str, Any]:
        """Calculates live real-time execution statistics."""
        passed = sum(1 for f in self.findings if f.status == FindingStatus.PASS)
        failed = sum(1 for f in self.findings if f.status == FindingStatus.FAIL)
        warn = sum(1 for f in self.findings if f.status == FindingStatus.WARN)
        unknown = sum(1 for f in self.findings if f.status == FindingStatus.UNKNOWN)
        na = sum(1 for f in self.findings if f.status == FindingStatus.NOT_APPLICABLE)
        errors = len(self.errors)
        total = len(self.findings)
        elapsed = time.time() - self.start_time

        crit = sum(1 for f in self.findings if f.status == FindingStatus.FAIL and f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.findings if f.status == FindingStatus.FAIL and f.severity == Severity.HIGH)
        med = sum(1 for f in self.findings if f.status == FindingStatus.FAIL and f.severity == Severity.MEDIUM)
        low = sum(1 for f in self.findings if f.status == FindingStatus.FAIL and f.severity == Severity.LOW)

        return {
            "total": total,
            "total_scheduled": self.total_scheduled,
            "passed": passed,
            "failed": failed,
            "warn": warn,
            "unknown": unknown,
            "na": na,
            "skipped": unknown + na,
            "errors": errors,
            "elapsed_seconds": elapsed,
            "critical_fails": crit,
            "high_fails": high,
            "medium_fails": med,
            "low_fails": low,
        }
