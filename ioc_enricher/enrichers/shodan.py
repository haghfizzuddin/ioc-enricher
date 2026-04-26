from __future__ import annotations
import httpx
from ..models import IOCType, ShodanResult

_BASE = "https://api.shodan.io"


def enrich_shodan(ioc: str, ioc_type: IOCType, api_key: str) -> ShodanResult:
    if ioc_type != IOCType.IP:
        raise ValueError("Shodan host lookup only supports IP addresses")

    with httpx.Client(timeout=15) as client:
        resp = client.get(f"{_BASE}/shodan/host/{ioc}", params={"key": api_key})
        resp.raise_for_status()
        data = resp.json()

    return ShodanResult(
        ip=data.get("ip_str"),
        org=data.get("org"),
        isp=data.get("isp"),
        country_name=data.get("country_name"),
        city=data.get("city"),
        ports=data.get("ports", []),
        hostnames=data.get("hostnames", []),
        vulns=list(data.get("vulns", {}).keys()),
        os=data.get("os"),
        tags=data.get("tags", []),
        last_update=data.get("last_update"),
    )
