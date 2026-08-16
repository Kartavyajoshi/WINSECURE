"""
WinSecure Rule Loader
"""
import glob
import json
import os
from typing import Dict, List, Optional
from winsecure.models.rule import Rule
from winsecure.rules.schema import validate_rule_dict


class RuleLoader:
    """Loads and validates JSON rule definitions from the rules catalog."""

    @staticmethod
    def load_from_directory(dir_path: str) -> List[Rule]:
        rules = []
        if not os.path.exists(dir_path):
            return rules

        pattern = os.path.join(dir_path, "*.json")
        for file_path in glob.glob(pattern):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    items = data if isinstance(data, list) else [data]
                    for item in items:
                        valid, errors = validate_rule_dict(item)
                        if valid:
                            rules.append(Rule.from_dict(item))
            except Exception:
                pass
        return rules

    @staticmethod
    def load_builtin_rules() -> List[Rule]:
        """Loads all built-in rules from the package distribution."""
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        rules_dir = os.path.join(base_dir, "rules")
        return RuleLoader.load_from_directory(rules_dir)
