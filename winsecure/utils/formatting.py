"""
WinSecure Terminal and Report Formatting Utilities
"""
import sys
from typing import Any, List, Optional

# Ensure standard output can handle UTF-8 / symbols safely on Windows
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def colorize(text: str, color_code: str, force: bool = False) -> str:
    """Wraps text in ANSI escape color codes if stdout is a TTY or force=True."""
    if force or (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()):
        return f"{color_code}{text}{Colors.RESET}"
    return text


def format_step(step_idx: int, total_steps: int, description: str, status: str = "✓") -> str:
    """Formats an orchestrator step line with encoding resilience."""
    display_status = status
    if sys.stdout.encoding and "cp125" in sys.stdout.encoding.lower():
        if status == "✓":
            display_status = "OK"
    status_colored = colorize(f"[{display_status}]", Colors.GREEN if status == "✓" or status == "OK" else Colors.YELLOW)
    return f"[{step_idx}/{total_steps}] {description.ljust(35)} {status_colored}"


def format_score_bar(score: float, width: int = 30) -> str:
    """Renders an ASCII/Unicode score bar."""
    filled = int((score / 100.0) * width)
    empty = width - filled
    char_fill = "#" if (sys.stdout.encoding and "cp125" in sys.stdout.encoding.lower()) else "█"
    char_empty = "-" if (sys.stdout.encoding and "cp125" in sys.stdout.encoding.lower()) else "░"
    bar = char_fill * filled + char_empty * empty
    if score >= 90:
        return colorize(bar, Colors.GREEN)
    elif score >= 80:
        return colorize(bar, Colors.CYAN)
    elif score >= 70:
        return colorize(bar, Colors.YELLOW)
    else:
        return colorize(bar, Colors.RED)
