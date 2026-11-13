"""Inteligencia sobre IPs: whois del dominio y consulta a Shodan InternetDB
(endpoint gratuito, sin API key ni créditos, dato pasivo por IP).

`ipinfo` sigue siendo tu script propio — se invoca vía subprocess porque
la lógica de geolocalización ya la tienes resuelta ahí y no aporta nada
reescribirla.
"""
from __future__ import annotations

import subprocess

from ..http_client import HttpClient
from ..models import IpIntel


def run_whois(domain: str, lines: int = 20) -> str:
    try:
        proc = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=15
        )
        return "\n".join(proc.stdout.splitlines()[:lines])
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return f"(whois no disponible: {exc})"


def run_ipinfo(ip: str) -> str:
    try:
        proc = subprocess.run(
            ["ipinfo", ip], capture_output=True, text=True, timeout=10
        )
        return proc.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return f"(ipinfo no disponible: {exc})"


def query_internetdb(client: HttpClient, ip: str) -> IpIntel:
    intel = IpIntel(ip=ip)
    result = client.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
    if not result.ok:
        return intel
    try:
        import json
        data = json.loads(result.text)
    except ValueError:
        return intel

    if "detail" in data:
        return intel  # IP no indexada por Shodan

    intel.shodan_ports = data.get("ports", [])
    intel.shodan_hostnames = data.get("hostnames", [])
    intel.shodan_cves = data.get("vulns", [])
    intel.shodan_tags = data.get("tags", [])
    return intel
