"""Inteligencia sobre IPs: whois del dominio, tu script `ipinfo` propio
(geolocalización + detección de hosting/CDN), y Shodan InternetDB
(endpoint gratuito, sin API key ni créditos, dato pasivo por IP).

`ipinfo` sigue siendo tu script propio — se invoca vía subprocess porque
la lógica de geolocalización ya la tienes resuelta ahí y no aporta nada
reescribirla. Parseamos su salida de texto para extraer "Hosting /
Datacenter" y "CDN / Proveedor" como campos estructurados.
"""
from __future__ import annotations

import json
import re
import subprocess

from ..http_client import HttpClient
from ..models import IpIntel

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_HOSTING_RE = re.compile(r"Hosting\s*/\s*Datacenter\s+(\S+)", re.IGNORECASE)
_CDN_RE = re.compile(r"CDN\s*/\s*Proveedor\s+(.+)", re.IGNORECASE)


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def run_whois(domain: str, lines: int = 20) -> str:
    try:
        proc = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=15
        )
        return "\n".join(proc.stdout.splitlines()[:lines])
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return f"(whois no disponible: {exc})"


def run_ipinfo(ip: str) -> str:
    """Devuelve la salida de tu script `ipinfo` YA limpia de códigos
    ANSI. Antes se guardaba/parseaba con los códigos de color intactos:
    si tu script colorea el valor junto al campo (p.ej. "Sí" en verde),
    el regex de abajo capturaba la secuencia de escape en vez del valor
    real, y por eso nunca coincidía con "sí"/"no" — de ahí el "sin
    determinar" aunque la salida a mano se viera perfectamente bien.
    """
    try:
        proc = subprocess.run(
            ["ipinfo", ip], capture_output=True, text=True, timeout=10
        )
        return strip_ansi(proc.stdout.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return f"(ipinfo no disponible: {exc})"


def parse_hosting(raw: str) -> bool | None:
    """Extrae "Hosting / Datacenter". None si el script no está
    disponible o el patrón no aparece — así el resto del reporte sigue
    funcionando, solo este dato concreto queda sin rellenar.
    """
    match = _HOSTING_RE.search(raw)
    if not match:
        return None
    value = match.group(1).strip().lower()
    if value in ("sí", "si", "yes", "true"):
        return True
    if value == "no":
        return False
    return None


def parse_cdn(raw: str) -> str | None:
    """Extrae "CDN / Proveedor" (p.ej. "Cloudflare"). Devuelve None si
    el campo no aparece o su valor es "—" (la convención de tu script
    para "sin CDN detectada").
    """
    match = _CDN_RE.search(raw)
    if not match:
        return None
    value = match.group(1).strip()
    if not value or value in ("—", "-"):
        return None
    return value


def query_internetdb(client: HttpClient, ip: str) -> IpIntel:
    intel = IpIntel(ip=ip)
    result = client.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
    if not result.ok:
        return intel
    try:
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


def gather_ip_intel(client: HttpClient, ip: str) -> IpIntel:
    """Punto de entrada único por IP: combina `ipinfo` (subprocess,
    bloqueante pero rápido) y Shodan InternetDB (HTTP) en un solo
    objeto IpIntel.
    """
    intel = query_internetdb(client, ip)
    raw = run_ipinfo(ip)
    intel.ipinfo_summary = raw
    intel.is_hosting = parse_hosting(raw)
    intel.cdn_provider = parse_cdn(raw)
    return intel
