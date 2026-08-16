"""
WinSecure System, Environment, and OS Utilities
"""
import os
import platform
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple


def is_windows() -> bool:
    """Returns True if the current operating system is Windows."""
    return platform.system().lower() == "windows" or os.name == "nt"


def is_admin() -> bool:
    """
    Checks whether the current execution has Windows administrative privileges.
    On non-Windows environments (such as testing environments), checks root or returns False.
    """
    if is_windows():
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin() != 0)
        except Exception:
            return False
    else:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False


def get_windows_os_info() -> Dict[str, Any]:
    """
    Extracts OS version, build, edition, and architecture.
    Uses registry / wmi / platform info safely.
    """
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "edition": "Windows 11 Enterprise",
        "build_number": 22631,
        "is_server": False,
        "architecture": "64-bit" if sys.maxsize > 2**32 else "32-bit",
    }
    
    if is_windows():
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                info["product_name"] = winreg.QueryValueEx(key, "ProductName")[0]
                info["display_version"] = winreg.QueryValueEx(key, "DisplayVersion")[0]
                info["current_build"] = winreg.QueryValueEx(key, "CurrentBuild")[0]
                info["build_number"] = int(info["current_build"])
                info["edition"] = info["product_name"]
                
                # Check server edition
                try:
                    install_type = winreg.QueryValueEx(key, "InstallationType")[0]
                    info["is_server"] = "server" in install_type.lower()
                except Exception:
                    pass
        except Exception:
            pass
    return info


def run_command(cmd: List[str], timeout: int = 15) -> Tuple[int, str, str]:
    """Safely executes a system command with timeout and sanitized output."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        return -1, "", str(e)


def run_powershell(script: str, timeout: int = 20) -> Tuple[int, str, str]:
    """Safely executes a PowerShell snippet via powershell.exe / pwsh."""
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", script
    ]
    return run_command(cmd, timeout=timeout)
