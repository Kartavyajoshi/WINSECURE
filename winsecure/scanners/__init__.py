"""
WinSecure Scanner Modules Subsystem Export (32 Specialized Modules)
"""
from winsecure.scanners.base import BaseScanner
from winsecure.scanners.defender_scanner import DefenderScanner
from winsecure.scanners.firewall_scanner import FirewallScanner
from winsecure.scanners.accounts_scanner import AccountsScanner
from winsecure.scanners.privileges_scanner import PrivilegesScanner
from winsecure.scanners.services_scanner import ServicesScanner
from winsecure.scanners.startup_scanner import StartupScanner
from winsecure.scanners.tasks_scanner import TasksScanner
from winsecure.scanners.registry_scanner import RegistryScanner
from winsecure.scanners.powershell_scanner import PowerShellScanner
from winsecure.scanners.audit_scanner import AuditScanner
from winsecure.scanners.eventlogs_scanner import EventLogsScanner
from winsecure.scanners.updates_scanner import UpdatesScanner
from winsecure.scanners.smb_scanner import SMBScanner
from winsecure.scanners.remote_scanner import RemoteScanner
from winsecure.scanners.network_scanner import NetworkScanner
from winsecure.scanners.encryption_scanner import EncryptionScanner
from winsecure.scanners.uac_scanner import UACScanner
from winsecure.scanners.smartscreen_scanner import SmartScreenScanner
from winsecure.scanners.software_scanner import SoftwareScanner
from winsecure.scanners.system_scanner import SystemScanner
from winsecure.scanners.applocker_scanner import AppLockerScanner
from winsecure.scanners.vbs_scanner import VBSScanner
from winsecure.scanners.laps_scanner import LAPSScanner
from winsecure.scanners.asr_scanner import ASRScanner
from winsecure.scanners.exploitguard_scanner import ExploitGuardScanner
from winsecure.scanners.schannel_scanner import SchannelScanner
from winsecure.scanners.kerberos_scanner import KerberosScanner
from winsecure.scanners.sandbox_scanner import SandboxScanner
from winsecure.scanners.spooler_scanner import SpoolerScanner
from winsecure.scanners.browser_scanner import BrowserScanner
from winsecure.scanners.ad_scanner import ADScanner
from winsecure.scanners.sysmon_scanner import SysmonScanner

ALL_SCANNERS = [
    DefenderScanner,
    FirewallScanner,
    AccountsScanner,
    PrivilegesScanner,
    ServicesScanner,
    StartupScanner,
    TasksScanner,
    RegistryScanner,
    PowerShellScanner,
    AuditScanner,
    EventLogsScanner,
    UpdatesScanner,
    SMBScanner,
    RemoteScanner,
    NetworkScanner,
    EncryptionScanner,
    UACScanner,
    SmartScreenScanner,
    SoftwareScanner,
    SystemScanner,
    AppLockerScanner,
    VBSScanner,
    LAPSScanner,
    ASRScanner,
    ExploitGuardScanner,
    SchannelScanner,
    KerberosScanner,
    SandboxScanner,
    SpoolerScanner,
    BrowserScanner,
    ADScanner,
    SysmonScanner,
]

__all__ = [
    "BaseScanner",
    "DefenderScanner",
    "FirewallScanner",
    "AccountsScanner",
    "PrivilegesScanner",
    "ServicesScanner",
    "StartupScanner",
    "TasksScanner",
    "RegistryScanner",
    "PowerShellScanner",
    "AuditScanner",
    "EventLogsScanner",
    "UpdatesScanner",
    "SMBScanner",
    "RemoteScanner",
    "NetworkScanner",
    "EncryptionScanner",
    "UACScanner",
    "SmartScreenScanner",
    "SoftwareScanner",
    "SystemScanner",
    "AppLockerScanner",
    "VBSScanner",
    "LAPSScanner",
    "ASRScanner",
    "ExploitGuardScanner",
    "SchannelScanner",
    "KerberosScanner",
    "SandboxScanner",
    "SpoolerScanner",
    "BrowserScanner",
    "ADScanner",
    "SysmonScanner",
    "ALL_SCANNERS",
]
