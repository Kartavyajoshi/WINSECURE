"""
WinSecure Base Scanner Interface
"""
import abc
from typing import Any, Dict, List, Optional
from winsecure.core.context import ScanContext
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.evidence import Evidence
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule


class BaseScanner(abc.ABC):
    """Abstract Base Class for all WinSecure Scanner Modules."""

    def __init__(self, context: ScanContext):
        self.context = context

    @property
    @abc.abstractmethod
    def metadata(self) -> ModuleMetadata:
        """Returns the module documentation and capability metadata."""
        pass

    @abc.abstractmethod
    def run(self) -> List[Finding]:
        """Executes all checks defined within the scanner module."""
        pass

    def create_finding(
        self,
        rule: Rule,
        status: FindingStatus,
        actual: str,
        confidence: float = 0.95,
        evidence_data: Optional[Any] = None,
        source: str = "Windows Configuration",
        collector_name: Optional[str] = None,
        command_executed: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Finding:
        """Constructs a normalized Finding object with sanitized evidence."""
        finding = Finding(
            id=rule.id,
            title=rule.title,
            category=rule.category,
            severity=rule.severity,
            status=status,
            confidence=confidence,
            description=rule.description,
            expected=rule.expected,
            actual=actual,
            impact=rule.impact,
            remediation=rule.remediation_guidance,
            references=rule.references,
            compliance=rule.compliance_mappings,
            mitre_attack=rule.mitre_attack,
            requires_admin=rule.requires_admin,
            tags=rule.tags,
        )

        if evidence_data is not None:
            ev = Evidence(
                source=source,
                collector=collector_name or self.metadata.name,
                data=evidence_data,
                command_executed=command_executed,
                notes=notes,
            )
            finding.add_evidence(ev)

        return finding
