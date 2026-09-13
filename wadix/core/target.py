"""
Target normalization, parsing, and validation module.
"""

import re
import ipaddress
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import Optional

@dataclass
class TargetInfo:
    raw_input: str
    url: str
    host: str
    port: int
    scheme: str
    path: str
    is_ip: bool
    safe_name: str

    def __str__(self):
        return self.url


DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def is_valid_ip(address: str) -> bool:
    """Check if address is a valid IPv4 or IPv6 string."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def is_valid_hostname(hostname: str) -> bool:
    """Validate that the hostname matches a domain name, localhost, or IP."""
    if not hostname or len(hostname) > 255:
        return False
    if hostname.lower() in ("localhost", "127.0.0.1", "::1"):
        return True
    if is_valid_ip(hostname):
        return True
    return bool(DOMAIN_REGEX.match(hostname))


def normalize_target(raw_target: str, default_scheme: str = "https") -> TargetInfo:
    """
    Safely parse, validate and normalize a raw target string.
    Raises ValueError if target is malformed or invalid.
    """
    cleaned = raw_target.strip()
    if not cleaned:
        raise ValueError("Target cannot be empty.")

    # Disallow control characters, whitespaces, shell characters
    if any(ch in cleaned for ch in [" ", "\t", "\n", "\r", ";", "&", "|", "`", "$", "<", ">", "\"", "'"]):
        raise ValueError("Target contains illegal characters or spaces.")

    # Prepend default scheme if missing
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"{default_scheme}://{cleaned}"

    parsed = urlparse(cleaned)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme '{scheme}'. Only http and https are supported.")

    # Extract hostname and port
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Could not extract a valid host from '{raw_target}'.")

    hostname = hostname.lower()
    if not is_valid_hostname(hostname):
        raise ValueError(f"Invalid domain or IP address: '{hostname}'")

    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80

    path = parsed.path or "/"

    # Construct clean URL
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        url = f"{scheme}://{hostname}{path}"
    else:
        url = f"{scheme}://{hostname}:{port}{path}"

    is_ip = is_valid_ip(hostname)

    # Safe folder name representation
    safe_name = f"{hostname}_{port}" if port not in (80, 443) else hostname
    safe_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", safe_name)

    return TargetInfo(
        raw_input=raw_target,
        url=url,
        host=hostname,
        port=port,
        scheme=scheme,
        path=path,
        is_ip=is_ip,
        safe_name=safe_name,
    )
