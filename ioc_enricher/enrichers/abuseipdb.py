from __future__ import annotations
import httpx
from ..models import IOCType, AbuseIPDBResult

_BASE = "https://api.abuseipdb.com/api/v2"


def enrich_abuseipdb(ioc: str, ioc_type: IOCType, api_key: str) -> AbuseIPDBResult:
    if ioc_type != IOCType.IP:
        raise ValueError("AbuseIPDB only supports IP addresses")

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": 90, "verbose": ""}

    with httpx.Client(timeout=15) as client:
        resp = client.get(f"{_BASE}/check", headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json().get("data", {})

    return AbuseIPDBResult(
        abuse_confidence_score=data.get("abuseConfidenceScore", 0),
        country_code=data.get("countryCode"),
        isp=data.get("isp"),
        domain=data.get("domain"),
        total_reports=data.get("totalReports", 0),
        last_reported_at=data.get("lastReportedAt"),
        is_whitelisted=data.get("isWhitelisted", False),
        usage_type=data.get("usageType"),
    )
