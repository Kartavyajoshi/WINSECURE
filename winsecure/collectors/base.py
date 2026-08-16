"""
WinSecure Base Collector Interface
"""
import abc
import time
from typing import Any, Dict, Optional
from winsecure.core.context import ScanContext
from winsecure.models.evidence import Evidence
from winsecure.utils.security import sanitize_data


class BaseCollector(abc.ABC):
    """Abstract base class for all security data collectors."""

    name: str = "BaseCollector"
    category: str = "General"

    def __init__(self, context: ScanContext):
        self.context = context
        self._cache: Optional[Dict[str, Any]] = None

    def collect(self) -> Dict[str, Any]:
        """Collects security artifacts with error isolation and timing."""
        start_t = time.perf_counter()
        try:
            raw_data = self._collect_internal()
            sanitized = sanitize_data(raw_data)
            self._cache = sanitized
            return sanitized
        except Exception as e:
            self.context.add_error(self.name, str(e))
            return {"error": str(e), "collected": False}

    @abc.abstractmethod
    def _collect_internal(self) -> Dict[str, Any]:
        """Internal collector implementation."""
        pass

    def create_evidence(self, key_path: str, data: Any, command: Optional[str] = None) -> Evidence:
        """Helper to create standardized Evidence objects."""
        return Evidence(
            source=key_path,
            collector=self.name,
            data=sanitize_data(data),
            command_executed=command,
            sanitized=True,
        )
