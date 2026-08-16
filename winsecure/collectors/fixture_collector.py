"""
WinSecure Synthetic Fixture Collector for Testing and Simulation
"""
import json
import os
from typing import Any, Dict, Optional
from winsecure.collectors.base import BaseCollector


class FixtureCollector(BaseCollector):
    name = "FixtureCollector"
    category = "Synthetic"

    def __init__(self, context, fixture_name_or_path: str):
        super().__init__(context)
        self.fixture_source = fixture_name_or_path

    def _collect_internal(self) -> Dict[str, Any]:
        path = self.fixture_source
        if not os.path.exists(path):
            # Check default fixtures dir
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            candidate = os.path.join(base_dir, "fixtures", f"{self.fixture_source}.json")
            if os.path.exists(candidate):
                path = candidate
            else:
                candidate2 = os.path.join(base_dir, "fixtures", self.fixture_source)
                if os.path.exists(candidate2):
                    path = candidate2

        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Populate context artifacts
                for k, v in data.items():
                    self.context.collected_artifacts[k] = v
                return data

        return {"error": f"Fixture file not found: {self.fixture_source}"}
