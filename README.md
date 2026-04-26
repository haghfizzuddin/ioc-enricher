# ioc-enricher

CLI tool to enrich threat intelligence indicators (IPs, domains, file hashes) using VirusTotal, AbuseIPDB, and Shodan.

Built for threat analysts and incident responders who need fast, consolidated context during triage — without switching between three browser tabs.

## Features

- Supports IPs, domains, and file hashes (MD5/SHA1/SHA256)
- Pulls detections, reputation, ASN, and threat names from **VirusTotal**
- Pulls abuse confidence score and ISP info from **AbuseIPDB** (IPs only)
- Pulls open ports, hostnames, and CVEs from **Shodan** (IPs only)
- Rich terminal output with color-coded risk levels
- `--json` flag for piping into SIEM or other tools
- Exit code `1` when any IOC is flagged malicious — CI/pipeline friendly

## Installation

```bash
git clone https://github.com/haghfizzuddin/ioc-enricher.git
cd ioc-enricher
pip install -e .
```

## Configuration

Copy `.env.example` to `.env` and fill in your API keys:

```bash
cp .env.example .env
```

Free tier keys work fine:
- [VirusTotal](https://www.virustotal.com/gui/join-us)
- [AbuseIPDB](https://www.abuseipdb.com/register)
- [Shodan](https://account.shodan.io/register)

## Usage

```bash
# Single IP
ioc-enricher 8.8.8.8

# Multiple IOCs at once
ioc-enricher 185.220.101.1 malware.example.com d41d8cd98f00b204e9800998ecf8427e

# JSON output
ioc-enricher 8.8.8.8 --json | jq '.[] | .virustotal.malicious'

# Skip a source
ioc-enricher 8.8.8.8 --no-shodan

# Pass keys inline (overrides .env)
ioc-enricher 8.8.8.8 --vt-key YOUR_KEY
```

## Output

```
╭─────────────────────────╮
│ 185.220.101.1  [ip]     │
╰─────────────────────────╯
  VirusTotal detections   18/94
  Reputation              -100
  Country                 DE
  AS Owner                Fraunhofer-Gesellschaft
  Threat names            Mirai, Hajime

  Abuse confidence        97%
  Total reports           1423
  ISP                     Frantech Solutions
  Usage type              Data Center/Web Hosting/Transit

  Org                     Frantech Solutions
  Country                 Germany
  Open ports              22, 80, 443, 8080
  Vulns                   CVE-2021-44228
```

## Running Tests

```bash
pip install pytest
pytest tests/
```
