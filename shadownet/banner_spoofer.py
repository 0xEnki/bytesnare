"""Configurable banner spoofing engine.

Sends plausible-looking service banners to waste attackers' time
and create the illusion of a real vulnerable service.
"""

from __future__ import annotations

import random
from typing import Dict, List, Optional

from .models import ShadowNetConfig


_DEFAULT_BANNERS: Dict[int, List[str]] = {
    22: [
        "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",
        "SSH-2.0-OpenSSH_6.9p1 Ubuntu-5ubuntu1",
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1",
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
    ],
    80: [
        "HTTP/1.1 200 OK\r\nServer: nginx/1.14.0 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Welcome to Ubuntu</h1></body></html>",
        "HTTP/1.1 403 Forbidden\r\nServer: Apache/2.4.29 (Debian)\r\nContent-Type: text/html\r\n\r\n<html><body><h1>403 Forbidden</h1></body></html>",
        "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<html><body><h1>It works!</h1></body></html>",
    ],
    443: [
        "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Welcome</h1></body></html>",
    ],
    445: [
        "\x00\x00\x00\x90\xFFSMB\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "\xFFSMB\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ],
    8080: [
        "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Apache Tomcat/7.0.52</h1></body></html>",
        "HTTP/1.1 401 Unauthorized\r\nServer: nginx/1.10.3\r\nWWW-Authenticate: Basic realm=\"Restricted Content\"\r\n\r\n",
    ],
    3306: [
        "\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x36\x00",
        "\x47\x00\x00\x00\x0a\x35\x2e\x37\x2e\x34\x31\x00",
    ],
    21: [
        "220 ProFTPD 1.3.5 Server (Debian) [::ffff:10.0.0.1]\r\n",
        "220 (vsFTPd 3.0.3)\r\n",
    ],
    23: [
        "\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27",
        "\r\nUbuntu 18.04 LTS\r\nlogin: ",
    ],
}


def choose_banner(port: int, config: Optional[ShadowNetConfig] = None) -> bytes:
    """Select a spoofed banner for the given port.

    Uses custom banners from config if available, otherwise falls
    back to the built-in default banner database.
    """
    if config and port in config.custom_banners:
        pool = config.custom_banners[port]
    else:
        pool = _DEFAULT_BANNERS.get(port, ["\r\n"])

    banner_str = random.choice(pool)
    return banner_str.encode("latin-1", errors="ignore")
