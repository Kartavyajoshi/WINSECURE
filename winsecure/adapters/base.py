"""
WinSecure Modular Adapter System
Provides extensible interfaces for security analysis tools, collectors, and scanners.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import time


class BaseAdapter(ABC):
    """
    Standardized adapter contract for security discovery, audit, and vulnerability analysis modules.
    Enforces normalized output and context awareness.
    """

    def __init__(self, name: str, version: str, capability: str):
        self.name = name
        self.version = version
        self.capability = capability
        self.timeout_sec: int = 60

    @abstractmethod
    def validate_requirements(self, context: Any) -> bool:
        """Verify prerequisite tools, permissions, and environment variables."""
        pass

    @abstractmethod
    def execute(self, target: str, context: Any) -> Dict[str, Any]:
        """
        Execute the assessment task and return a normalized result dictionary:
        {
            "module": self.name,
            "target": target,
            "status": "completed" | "failed" | "skipped",
            "findings": [...],
            "evidence": [...],
            "metadata": {...},
            "risk": {...}
        }
        """
        pass

    def extract_evidence(self, raw_data: Any) -> List[Dict[str, Any]]:
        """Normalize raw scanner/tool outputs into standardized evidence records."""
        return []

    def format_result(
        self,
        target: str,
        status: str,
        findings: Optional[List[Dict[str, Any]]] = None,
        evidence: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        risk: Optional[Dict[str, Any]] = None,
        execution_time_ms: float = 0.0,
    ) -> Dict[str, Any]:
        """Produce the normalized assessment output schema."""
        return {
            "module": self.name,
            "version": self.version,
            "capability": self.capability,
            "target": target,
            "status": status,
            "execution_time_ms": round(execution_time_ms, 2),
            "findings": findings or [],
            "evidence": evidence or [],
            "metadata": metadata or {},
            "risk": risk or {},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
