from __future__ import annotations
import re
import ipaddress
from .models import IOCType

_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def detect_ioc_type(value: str) -> IOCType:
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return IOCType.IP
    except ValueError:
        pass
    if _MD5_RE.match(value) or _SHA1_RE.match(value) or _SHA256_RE.match(value):
        return IOCType.HASH
    if _DOMAIN_RE.match(value):
        return IOCType.DOMAIN
    return IOCType.UNKNOWN
