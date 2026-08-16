"""
Unit Tests for Rules Engine & Catalog
"""
import unittest
from winsecure.rules import RuleLoader, RuleRegistry, validate_rule_dict
from winsecure.models import Severity


class TestRulesEngine(unittest.TestCase):
    def test_validate_rule_schema(self):
        valid_dict = {
            "id": "WS-TEST-001",
            "title": "Valid Rule",
            "category": "Test",
            "severity": "High",
            "description": "Desc",
            "expected": "Expected",
            "impact": "Impact",
            "remediation_guidance": "Remediation",
            "check_type": "registry"
        }
        is_valid, errors = validate_rule_dict(valid_dict)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

        invalid_dict = {"id": "WS-TEST-002"}
        is_valid_inv, errors_inv = validate_rule_dict(invalid_dict)
        self.assertFalse(is_valid_inv)
        self.assertGreater(len(errors_inv), 0)

    def test_load_builtin_rules(self):
        rules = RuleLoader.load_builtin_rules()
        self.assertGreater(len(rules), 15)

        reg = RuleRegistry.create_default()
        rule_def = reg.get("WS-DEF-001")
        self.assertIsNotNone(rule_def)
        self.assertEqual(rule_def.category, "Defender")
        self.assertEqual(rule_def.severity, Severity.CRITICAL)


if __name__ == "__main__":
    unittest.main()
