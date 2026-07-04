"""Active host mitigation — system-level firewall blocking.

Detects the host OS and invokes the appropriate firewall command
to permanently DROP traffic from an attacker IP.
"""

from __future__ import annotations

import platform
import subprocess
from typing import List, Tuple

from .logger import get_logger


logger = get_logger()


def _run_cmd(cmd: List[str], timeout: float = 10.0) -> Tuple[int, str, str]:
    """Execute a system command safely and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "command timed out"
    except PermissionError:
        return 126, "", "permission denied (not root?)"
    except OSError as exc:
        return 1, "", str(exc)


def block_ip_linux(ip: str) -> Tuple[bool, str]:
    """Block an IP address using iptables (Linux).

    Checks for an existing rule first to avoid duplicates, then
    inserts a DROP rule at position 1 in the INPUT chain.

    Returns
    -------
    (success, detail_message)
    """
    check_cmd = ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
    insert_cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]

    rc, _, _ = _run_cmd(check_cmd)
    if rc == 0:
        return True, "already blocked (iptables rule exists)"

    rc, out, err = _run_cmd(insert_cmd)
    if rc == 0:
        logger.info("Blocked %s via iptables", ip)
        return True, "blocked (iptables)"
    return False, f"iptables failed [{rc}]: {err or out}"


def block_ip_windows(ip: str, rule_prefix: str = "ShadowNet_Block_") -> Tuple[bool, str]:
    """Block an IP address using netsh advfirewall (Windows).

    Requires administrator privileges.
    """
    rule_name = f"{rule_prefix}{ip}".replace(":", "_")
    add_cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
    ]
    rc, out, err = _run_cmd(add_cmd)
    if rc == 0:
        logger.info("Blocked %s via netsh advfirewall", ip)
        return True, "blocked (netsh advfirewall)"
    return False, f"netsh failed [{rc}]: {err or out}"


def block_ip(
    ip: str,
    rule_prefix: str = "ShadowNet_Block_",
) -> Tuple[bool, str]:
    """Block an attacker IP on the host firewall.

    Automatically selects the correct firewall backend based on the
    host operating system.

    Parameters
    ----------
    ip:
        IPv4 or IPv6 address to block.
    rule_prefix:
        Prefix for the firewall rule name (Windows only).

    Returns
    -------
    (success, detail_message)
    """
    system = platform.system().lower()
    if "linux" in system:
        return block_ip_linux(ip)
    if "windows" in system:
        return block_ip_windows(ip, rule_prefix)
    return False, f"unsupported OS: {platform.system()}"


def unblock_ip(ip: str, rule_prefix: str = "ShadowNet_Block_") -> Tuple[bool, str]:
    """Remove a firewall block rule for the given IP.

    Currently supports Linux iptables only.  Useful for cleanup
    during controlled shutdown or unblocking.
    """
    system = platform.system().lower()
    if "linux" in system:
        delete_cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        rc, out, err = _run_cmd(delete_cmd)
        if rc == 0:
            return True, f"unblocked {ip} (iptables)"
        return False, f"iptables delete failed [{rc}]: {err or out}"
    if "windows" in system:
        rule_name = f"{rule_prefix}{ip}".replace(":", "_")
        delete_cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ]
        rc, out, err = _run_cmd(delete_cmd)
        if rc == 0:
            return True, f"unblocked {ip} (netsh)"
        return False, f"netsh delete failed [{rc}]: {err or out}"
    return False, f"unsupported OS: {platform.system()}"
