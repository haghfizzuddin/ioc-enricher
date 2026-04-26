from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    UNKNOWN = "unknown"


class VTResult(BaseModel):
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total: int = 0
    reputation: int = 0
    tags: list[str] = []
    last_analysis_date: str | None = None
    country: str | None = None
    asn: str | None = None
    as_owner: str | None = None
    categories: dict[str, str] = {}
    threat_names: list[str] = []
    raw: dict[str, Any] = {}


class AbuseIPDBResult(BaseModel):
    abuse_confidence_score: int = 0
    country_code: str | None = None
    isp: str | None = None
    domain: str | None = None
    total_reports: int = 0
    last_reported_at: str | None = None
    is_whitelisted: bool = False
    usage_type: str | None = None


class ShodanResult(BaseModel):
    ip: str | None = None
    org: str | None = None
    isp: str | None = None
    country_name: str | None = None
    city: str | None = None
    ports: list[int] = []
    hostnames: list[str] = []
    vulns: list[str] = []
    os: str | None = None
    tags: list[str] = []
    last_update: str | None = None


class EnrichmentResult(BaseModel):
    ioc: str
    ioc_type: IOCType
    virustotal: VTResult | None = None
    abuseipdb: AbuseIPDBResult | None = None
    shodan: ShodanResult | None = None
    errors: dict[str, str] = {}
