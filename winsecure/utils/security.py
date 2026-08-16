"""
WinSecure Security and Sanitization Utilities
"""
import re
from typing import Any, Dict, List, Union

# Regex patterns for sensitive data that MUST NEVER leak into evidence or logs
PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd|secret|apikey|api_key|token|auth_token|bearer)\s*[:=]\s*["\']?([^"\'\s,;]+)["\']?'), r'\1: [REDACTED_SECRET]'),
    (re.compile(r'(?i)(recovery[-_]?key|bitlocker[-_]?key)\s*[:=]\s*["\']?([0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6})["\']?'), r'\1: [REDACTED_BITLOCKER_KEY]'),
    (re.compile(r'[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}-[0-9]{6}'), '[REDACTED_BITLOCKER_KEY]'),
    (re.compile(r'-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]'),
    (re.compile(r'(?i)(ntlm|lm|sam)[-_]?hash\s*[:=]\s*["\']?([a-f0-9]{32})["\']?'), r'\1_hash: [REDACTED_HASH]'),
]


def sanitize_text(text: str) -> str:
    """Sanitizes text by removing passwords, keys, tokens, and secrets."""
    if not isinstance(text, str):
        return str(text)
    sanitized = text
    for pattern, replacement in PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def sanitize_data(data: Any) -> Any:
    """Recursively sanitizes dictionaries, lists, strings, and structures."""
    if isinstance(data, str):
        return sanitize_text(data)
    elif isinstance(data, dict):
        sanitized_dict = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in ["password", "secret", "private_key", "token", "recovery_key", "auth"]):
                sanitized_dict[k] = "[REDACTED]"
            else:
                sanitized_dict[k] = sanitize_data(v)
        return sanitized_dict
    elif isinstance(data, list):
        return [sanitize_data(item) for item in data]
    elif isinstance(data, tuple):
        return tuple(sanitize_data(item) for item in data)
    return data
