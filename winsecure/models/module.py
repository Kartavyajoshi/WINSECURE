"""
WinSecure Scanner Module Metadata and Health Models
"""
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class ModuleMetadata:
    id: str
    name: str
    purpose: str
    category: str
    version: str = "1.0.0"
    author: str = "WinSecure Security Engineering"
    inputs: List[str] = field(default_factory=list)
    collectors: List[str] = field(default_factory=list)
    checks: List[str] = field(default_factory=list)
    outputs: str = "Normalized Findings (JSON Schema v2)"
    dependencies: List[str] = field(default_factory=lambda: ["Built-in Python Standard Library", "Win32 APIs / PowerShell"])
    supported_os: List[str] = field(default_factory=lambda: ["Windows 10", "Windows 11", "Windows Server 2016+"])
    requires_admin: bool = False
    admin_recommended: bool = True
    performance_impact: str = "Low (< 50ms execution)"
    security_considerations: str = "Read-only inspection; non-intrusive; no credentials stored or transmitted"
    compliance_frameworks: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScannerHealth:
    scanner_id: str
    name: str
    category: str
    status: str  # COMPLETED, FAILED, SKIPPED, PARTIAL
    checks_count: int = 0
    passed_count: int = 0
    failed_count: int = 0
    warn_count: int = 0
    unknown_count: int = 0
    na_count: int = 0
    error_count: int = 0
    execution_time_ms: float = 0.0
    requires_admin: bool = False
    coverage_percent: float = 100.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
