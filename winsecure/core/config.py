"""
WinSecure Configuration Management
"""
import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ScanConfig:
    profile: str = "standard"  # standard, hardened, quick, full
    output_dir: str = "./WinSecure-Report"
    formats: List[str] = field(default_factory=lambda: ["html", "json", "csv", "sqlite", "web"])
    include_benchmarks: bool = True
    include_remediation: bool = True
    include_ai_insights: bool = True
    include_inventory: bool = True
    offline_mode: bool = True
    timeout_per_check: int = 10
    log_level: str = "INFO"
    fixture_path: Optional[str] = None
    custom_rules_dir: Optional[str] = None
    db_path: Optional[str] = None

    def __post_init__(self):
        self.output_dir = os.path.abspath(self.output_dir)
        if not self.db_path:
            self.db_path = os.path.join(self.output_dir, "winsecure_history.db")
