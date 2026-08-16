"""
Unit Tests for Security Collectors & Sanitization
"""
import unittest
from winsecure.core.config import ScanConfig
from winsecure.core.context import ScanContext
from winsecure.collectors import RegistryCollector, BaseCollector
from winsecure.utils.security import sanitize_data, sanitize_text


class TestCollectorsAndSanitization(unittest.TestCase):
    def test_sanitize_passwords_and_tokens(self):
        raw = "User password=SuperSecretPassword123! and recovery_key=123456-789012-345678-901234-567890-123456-789012-345678"
        sanitized = sanitize_text(raw)
        self.assertNotIn("SuperSecretPassword123!", sanitized)
        self.assertNotIn("123456-789012", sanitized)
        self.assertIn("[REDACTED", sanitized)

    def test_sanitize_dict(self):
        raw_dict = {
            "username": "admin",
            "password": "Password123!",
            "nested": {
                "secret_token": "abcdef1234567890"
            }
        }
        sanitized = sanitize_data(raw_dict)
        self.assertEqual(sanitized["username"], "admin")
        self.assertEqual(sanitized["password"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["secret_token"], "[REDACTED]")

    def test_base_collector_error_handling(self):
        class FaultyCollector(BaseCollector):
            name = "FaultyCollector"
            def _collect_internal(self):
                raise RuntimeError("Simulated connection failure")

        ctx = ScanContext(ScanConfig())
        fc = FaultyCollector(ctx)
        res = fc.collect()
        self.assertIn("error", res)
        self.assertEqual(len(ctx.errors), 1)


if __name__ == "__main__":
    unittest.main()
