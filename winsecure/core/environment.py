"""
WinSecure Environment Detection and Validation
"""
import os
import sys
import shutil
from typing import Tuple
from winsecure.core.context import ScanContext
from winsecure.utils.system import is_windows, is_admin, get_windows_os_info


class EnvironmentValidator:
    """Validates runtime prerequisites, OS attributes, and directories."""

    @staticmethod
    def validate(context: ScanContext) -> Tuple[bool, str]:
        # 1. Python version check
        if sys.version_info < (3, 8):
            return False, f"Python 3.8+ required. Current version: {sys.version}"

        # 2. OS detection
        context.is_windows = is_windows()
        context.is_admin = is_admin()
        context.os_info = get_windows_os_info()

        # 3. Privilege coverage calculation
        if context.is_admin:
            context.privilege_coverage_percent = 100.0
        else:
            # Standard user has access to user registry, query APIs, WMI, public firewall, etc.
            context.privilege_coverage_percent = 78.5

        # 4. Prepare Output Directory
        try:
            os.makedirs(context.config.output_dir, exist_ok=True)
            os.makedirs(os.path.join(context.config.output_dir, "data"), exist_ok=True)
            os.makedirs(os.path.join(context.config.output_dir, "evidence"), exist_ok=True)
            os.makedirs(os.path.join(context.config.output_dir, "assets"), exist_ok=True)
        except Exception as e:
            return False, f"Failed to create output directory {context.config.output_dir}: {e}"

        return True, "Environment validated successfully."
