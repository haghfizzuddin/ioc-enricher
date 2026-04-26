from __future__ import annotations
import json
import os
import sys
import click
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text

from .models import IOCType, EnrichmentResult
from .utils import detect_ioc_type
from .enrichers import enrich_virustotal, enrich_abuseipdb, enrich_shodan

load_dotenv()
console = Console()


def _vt_color(malicious: int) -> str:
    if malicious >= 10:
        return "bold red"
    if malicious >= 3:
        return "yellow"
    if malicious >= 1:
        return "orange3"
    return "green"


def _abuse_color(score: int) -> str:
    if score >= 75:
        return "bold red"
    if score >= 25:
        return "yellow"
    return "green"


def _render_result(result: EnrichmentResult) -> None:
    title = Text()
    title.append(result.ioc, style="bold white")
    title.append(f"  [{result.ioc_type.value}]", style="dim")
    console.print(Panel(title, expand=False))

    if result.virustotal:
        vt = result.virustotal
        color = _vt_color(vt.malicious)
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        t.add_column(style="dim", width=22)
        t.add_column()
        t.add_row("VirusTotal detections", Text(f"{vt.malicious}/{vt.total}", style=color))
        if vt.reputation:
            t.add_row("Reputation", str(vt.reputation))
        if vt.country:
            t.add_row("Country", vt.country)
        if vt.as_owner:
            t.add_row("AS Owner", vt.as_owner)
        if vt.threat_names:
            t.add_row("Threat names", ", ".join(vt.threat_names[:5]))
        if vt.tags:
            t.add_row("Tags", ", ".join(vt.tags))
        console.print(t)

    if result.abuseipdb:
        ab = result.abuseipdb
        color = _abuse_color(ab.abuse_confidence_score)
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        t.add_column(style="dim", width=22)
        t.add_column()
        t.add_row("Abuse confidence", Text(f"{ab.abuse_confidence_score}%", style=color))
        t.add_row("Total reports", str(ab.total_reports))
        if ab.isp:
            t.add_row("ISP", ab.isp)
        if ab.usage_type:
            t.add_row("Usage type", ab.usage_type)
        if ab.last_reported_at:
            t.add_row("Last reported", ab.last_reported_at)
        console.print(t)

    if result.shodan:
        sh = result.shodan
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        t.add_column(style="dim", width=22)
        t.add_column()
        if sh.org:
            t.add_row("Org", sh.org)
        if sh.country_name:
            t.add_row("Country", sh.country_name)
        if sh.city:
            t.add_row("City", sh.city)
        if sh.ports:
            t.add_row("Open ports", ", ".join(str(p) for p in sorted(sh.ports)))
        if sh.vulns:
            t.add_row("Vulns", Text(", ".join(sh.vulns[:5]), style="red"))
        if sh.hostnames:
            t.add_row("Hostnames", ", ".join(sh.hostnames[:3]))
        console.print(t)

    if result.errors:
        for source, err in result.errors.items():
            console.print(f"  [dim][{source}] {err}[/dim]")

    console.print()


@click.command()
@click.argument("iocs", nargs=-1, required=True)
@click.option("--vt-key", envvar="VT_API_KEY", help="VirusTotal API key")
@click.option("--abuse-key", envvar="ABUSEIPDB_API_KEY", help="AbuseIPDB API key")
@click.option("--shodan-key", envvar="SHODAN_API_KEY", help="Shodan API key")
@click.option("--json", "output_json", is_flag=True, help="Output raw JSON")
@click.option("--no-vt", is_flag=True, help="Skip VirusTotal")
@click.option("--no-abuse", is_flag=True, help="Skip AbuseIPDB")
@click.option("--no-shodan", is_flag=True, help="Skip Shodan")
def main(iocs, vt_key, abuse_key, shodan_key, output_json, no_vt, no_abuse, no_shodan):
    """Enrich IOCs (IPs, domains, hashes) using VirusTotal, AbuseIPDB, and Shodan."""
    results = []

    for ioc in iocs:
        ioc = ioc.strip()
        ioc_type = detect_ioc_type(ioc)

        if ioc_type == IOCType.UNKNOWN:
            console.print(f"[yellow]Skipping unrecognised IOC:[/yellow] {ioc}")
            continue

        result = EnrichmentResult(ioc=ioc, ioc_type=ioc_type)

        if not no_vt and vt_key:
            try:
                result.virustotal = enrich_virustotal(ioc, ioc_type, vt_key)
            except Exception as e:
                result.errors["virustotal"] = str(e)

        if not no_abuse and abuse_key and ioc_type == IOCType.IP:
            try:
                result.abuseipdb = enrich_abuseipdb(ioc, ioc_type, abuse_key)
            except Exception as e:
                result.errors["abuseipdb"] = str(e)

        if not no_shodan and shodan_key and ioc_type == IOCType.IP:
            try:
                result.shodan = enrich_shodan(ioc, ioc_type, shodan_key)
            except Exception as e:
                result.errors["shodan"] = str(e)

        results.append(result)

    if output_json:
        click.echo(json.dumps([r.model_dump() for r in results], indent=2))
    else:
        for r in results:
            _render_result(r)

    has_malicious = any(
        r.virustotal and r.virustotal.malicious > 0 for r in results
    )
    sys.exit(1 if has_malicious else 0)
