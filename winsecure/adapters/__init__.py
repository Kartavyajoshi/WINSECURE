"""
WinSecure Adapters Package
"""
from winsecure.adapters.base import BaseAdapter
from winsecure.adapters.host_discovery import HostDiscoveryAdapter
from winsecure.adapters.service_analyzer import ServiceAnalyzerAdapter
from winsecure.adapters.config_auditor import ConfigAuditorAdapter
from winsecure.adapters.vulnerability_analyzer import VulnerabilityAnalyzerAdapter
from winsecure.adapters.policy_compliance import PolicyComplianceAdapter

ALL_ADAPTERS = [
    HostDiscoveryAdapter,
    ServiceAnalyzerAdapter,
    ConfigAuditorAdapter,
    VulnerabilityAnalyzerAdapter,
    PolicyComplianceAdapter,
]

__all__ = [
    "BaseAdapter",
    "HostDiscoveryAdapter",
    "ServiceAnalyzerAdapter",
    "ConfigAuditorAdapter",
    "VulnerabilityAnalyzerAdapter",
    "PolicyComplianceAdapter",
    "ALL_ADAPTERS",
]
