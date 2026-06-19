"""
utils.py - Helper utilizes: privilege check, banner, input paring.
"""

import os
import sys
import socket
import platform
from typing import Optional


def is_root() -> bool:
    """Returns True if the current process has root/admin privileges."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    

def require_root_profiles() -> bool:
    """Returns the set of ScanProfile values that requires root."""
    from scanner import ScanProfile
    return {ScanProfile.OS, ScanProfile.VULN, ScanProfile.STEALTH, ScanProfile.UDP}


def check_privileges(profile) -> Optional[str]:
    """Returns a warning string if the profile needs root but we don't have it."""
    from scanner import ScanProfile
    if profile in require_root_profiles() and not is_root():
        return (
            f"Profile '{profile.value}' typically requires root/administrator"
            "Privileges. Result may be incomplete."
        )
    return None


def  resolve_hostname(host: str) -> Optional[str]:
    """Resolve a hostname to an IP string, or None on failure."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None
    

def parse_port_range(port_str: str) -> str:
    """
    Convert a human-friendly port  spec to nmap format.
    Examples:
         "80"       → "80"
         "80,443"   → "80,443"
         "1-1024"   → "1-1024"
         "top100"   → "--top-ports 100"
    """
    port_str = port_str.strip().lower()
    if port_str.startswith("top"):
        n = port_str[3:]
        return f"--top-ports {n}"
    return f"-p {port_str}"


def banner() -> str:
    py_ver = platform.python_version()
    os_name = platform.system()
    privilege = "root" if is_root() else "unprivileged"
    return f"""
╔══════════════════════════════════════════════╗
║          Python Nmap Port Scanner            ║
║  Python {py_ver:<8}  OS: {os_name:<10}  [{privilege}]  ║
╚══════════════════════════════════════════════╝
"""


def print_progress(msg: str) -> None:
    """Simple stdout progress printer."""
    print(msg, flush=True)


def confirm(prompt: str) -> bool:
    """"Ask user for y/n confirmation."""
    ans = input(f"{prompt} [Y/N]: ").strip().lower()
    return ans in ("y", "yes")

