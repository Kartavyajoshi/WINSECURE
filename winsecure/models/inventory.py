"""
WinSecure System Inventory Data Model
"""
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class NetworkInterface:
    name: str
    description: str
    mac_address: str
    ipv4_addresses: List[str] = field(default_factory=list)
    dhcp_enabled: bool = True
    status: str = "Up"


@dataclass
class InstalledApp:
    name: str
    version: str
    vendor: str
    install_date: Optional[str] = None
    install_location: Optional[str] = None
    is_64bit: bool = True


@dataclass
class SystemInventory:
    hostname: str = "Unknown"
    domain_or_workgroup: str = "WORKGROUP"
    os_name: str = "Microsoft Windows"
    os_version: str = "10.0"
    os_build: str = "22631"
    os_edition: str = "Windows 11 Pro"
    os_architecture: str = "64-bit"
    install_date: str = "Unknown"
    uptime_seconds: int = 0
    bios_version: str = "Unknown"
    bios_mode: str = "UEFI"
    secure_boot: bool = False
    tpm_version: str = "None"
    tpm_present: bool = False
    cpu_model: str = "Unknown"
    cpu_cores: int = 1
    total_ram_mb: int = 0
    free_ram_mb: int = 0
    disks: List[Dict[str, Any]] = field(default_factory=list)
    network_interfaces: List[Dict[str, Any]] = field(default_factory=list)
    listening_ports: List[Dict[str, Any]] = field(default_factory=list)
    local_users: List[Dict[str, Any]] = field(default_factory=list)
    services_summary: Dict[str, int] = field(default_factory=lambda: {"total": 0, "running": 0, "stopped": 0, "disabled": 0})
    installed_software: List[Dict[str, Any]] = field(default_factory=list)
    hotfixes_count: int = 0
    security_features: Dict[str, bool] = field(default_factory=lambda: {
        "vbs_enabled": False,
        "hvci_enabled": False,
        "credential_guard": False,
        "secure_boot": False,
        "bitlocker_active": False,
        "defender_active": False,
        "firewall_active": False,
        "uac_active": False,
    })

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
