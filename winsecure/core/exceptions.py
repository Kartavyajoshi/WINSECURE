"""
WinSecure Custom Exceptions
"""


class WinSecureException(Exception):
    """Base exception for all WinSecure errors."""
    pass


class EnvironmentException(WinSecureException):
    """Raised when the execution environment fails validation."""
    pass


class CollectorException(WinSecureException):
    """Raised when a security data collector encounters an error."""
    pass


class RuleEvaluationException(WinSecureException):
    """Raised during rule evaluation failures."""
    pass


class ComplianceException(WinSecureException):
    """Raised during compliance framework assessment."""
    pass


class StorageException(WinSecureException):
    """Raised on SQLite database or persistent storage errors."""
    pass


class ReportingException(WinSecureException):
    """Raised during report or website generation."""
    pass
