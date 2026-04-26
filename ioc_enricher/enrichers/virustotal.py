from __future__ import annotations
import httpx
from ..models import IOCType, VTResult

_BASE = "https://www.virustotal.com/api/v3"


def enrich_virustotal(ioc: str, ioc_type: IOCType, api_key: str) -> VTResult:
    headers = {"x-apikey": api_key}

    if ioc_type == IOCType.IP:
        url = f"{_BASE}/ip_addresses/{ioc}"
    elif ioc_type == IOCType.DOMAIN:
        url = f"{_BASE}/domains/{ioc}"
    elif ioc_type == IOCType.HASH:
        url = f"{_BASE}/files/{ioc}"
    else:
        raise ValueError(f"Unsupported IOC type for VirusTotal: {ioc_type}")

    with httpx.Client(timeout=15) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    threat_names = list(
        {
            r.get("result")
            for r in attrs.get("last_analysis_results", {}).values()
            if r.get("category") == "malicious" and r.get("result")
        }
    )

    return VTResult(
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
        total=sum(stats.values()),
        reputation=attrs.get("reputation", 0),
        tags=attrs.get("tags", []),
        last_analysis_date=str(attrs.get("last_analysis_date", "")),
        country=attrs.get("country"),
        asn=str(attrs.get("asn", "")) or None,
        as_owner=attrs.get("as_owner"),
        categories=attrs.get("categories", {}),
        threat_names=threat_names,
        raw=attrs,
    )
