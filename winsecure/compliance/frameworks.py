"""
WinSecure Compliance Framework Metadata
"""
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class FrameworkInfo:
    id: str
    name: str
    version: str
    authority: str
    url: str
    description: str


SUPPORTED_FRAMEWORKS: Dict[str, FrameworkInfo] = {
    "cis_win11_enterprise": FrameworkInfo(
        id="cis_win11_enterprise",
        name="CIS Microsoft Windows 11 Enterprise Benchmark",
        version="5.0.1",
        authority="Center for Internet Security (CIS)",
        url="https://www.cisecurity.org/cis-benchmarks/",
        description="Consensus-developed secure baseline configuration recommendations for Windows 11 Enterprise."
    ),
    "cis_win11_standalone": FrameworkInfo(
        id="cis_win11_standalone",
        name="CIS Microsoft Windows 11 Stand-alone Benchmark",
        version="5.0.0",
        authority="Center for Internet Security (CIS)",
        url="https://www.cisecurity.org/cis-benchmarks/",
        description="Secure baseline recommendations for non-domain Windows 11 endpoints."
    ),
    "ms_security_baseline": FrameworkInfo(
        id="ms_security_baseline",
        name="Microsoft Windows Security Baseline",
        version="Win11-23H2",
        authority="Microsoft Security Compliance Toolkit",
        url="https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines",
        description="Official Microsoft recommended security configuration baseline settings."
    ),
    "nist_sp800_53": FrameworkInfo(
        id="nist_sp800_53",
        name="NIST SP 800-53 Security and Privacy Controls",
        version="Rev 5",
        authority="National Institute of Standards and Technology (NIST)",
        url="https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
        description="Federal security control catalog for federal information systems and organizations."
    ),
    "nist_csf": FrameworkInfo(
        id="nist_csf",
        name="NIST Cybersecurity Framework (CSF)",
        version="2.0",
        authority="National Institute of Standards and Technology (NIST)",
        url="https://www.nist.gov/cyberframework",
        description="Guidance for managing and reducing cybersecurity risk across organizations."
    ),
    "disa_stig": FrameworkInfo(
        id="disa_stig",
        name="DISA Microsoft Windows 11 Security Technical Implementation Guide (STIG)",
        version="V1R3",
        authority="Defense Information Systems Agency (DISA)",
        url="https://public.cyber.mil/stigs/",
        description="Department of Defense cybersecurity configuration standards for military systems."
    ),
}
