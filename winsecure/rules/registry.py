"""
WinSecure Rule Registry
"""
from typing import Dict, List, Optional
from winsecure.models.rule import Rule
from winsecure.rules.loader import RuleLoader


class RuleRegistry:
    """Central registry of executable security rules indexed by ID and Category."""

    def __init__(self):
        self._rules: Dict[str, Rule] = {}
        self._by_category: Dict[str, List[Rule]] = {}

    def register(self, rule: Rule) -> None:
        self._rules[rule.id] = rule
        if rule.category not in self._by_category:
            self._by_category[rule.category] = []
        self._by_category[rule.category].append(rule)

    def register_many(self, rules: List[Rule]) -> None:
        for r in rules:
            self.register(r)

    def get(self, rule_id: str) -> Optional[Rule]:
        return self._rules.get(rule_id)

    def get_by_category(self, category: str) -> List[Rule]:
        return self._by_category.get(category, [])

    def get_all(self) -> List[Rule]:
        return list(self._rules.values())

    @classmethod
    def create_default(cls) -> "RuleRegistry":
        reg = cls()
        reg.register_many(RuleLoader.load_builtin_rules())
        return reg
