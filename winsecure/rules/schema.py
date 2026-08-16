"""
WinSecure Rule Schema Validation
"""
from typing import Any, Dict, List, Tuple


def validate_rule_dict(rule_dict: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validates that a rule definition dictionary contains all required fields."""
    required_fields = ["id", "title", "category", "severity", "description", "expected", "impact", "remediation_guidance"]
    errors = []
    for field in required_fields:
        if field not in rule_dict or not rule_dict[field]:
            errors.append(f"Missing required field: '{field}'")
    
    if "check_type" not in rule_dict:
        errors.append("Missing 'check_type'")
    
    return len(errors) == 0, errors
