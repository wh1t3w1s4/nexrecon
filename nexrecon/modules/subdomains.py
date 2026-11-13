"""Descubrimiento de subdominios desde varias fuentes.

crt.sh se parsea con el módulo estándar `csv` (robusto frente a campos
con comas dentro de comillas, el mismo problema que resolvimos en bash
delegando a Python — aquí ya estamos en Python, así que es nativo).
El scraping de Shodan usa BeautifulSoup en vez de sed/grep sobre HTML,
mucho más resistente a pequeños cambios de formato.
"""
from __future__ import annotations

import csv
import io
import json
import subprocess
import time

from bs4 import BeautifulSoup

from ..http_client import HttpClient


def run_subfinder(domain: str, timeout: int = 120) -> list[str]:
    try:
        proc = subprocess.run(
            ["subfinder", "-silent", "-d", domain],
            capture_output=True, text=True, timeout=timeout,
        )
        return sorted({line.strip() for line in proc.stdout.splitlines() if line.strip()})
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def query_crtsh(client: HttpClient, domain: str, max_retries: int = 4) -> list[str]:
    wait = 3
    for attempt in range(max_retries):
        result = client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30
        )
        if result.ok and result.text.strip():
            try:
                data = json.loads(result.text)
                names = set()
                for entry in data:
                    for line in entry.get("name_value", "").split("\n"):
                        line = line.strip().lstrip("*.")
                        if line:
                            names.add(line)
                return sorted(names)
            except ValueError:
                pass
        time.sleep(wait)
        wait *= 2

    # Fallback CSV
    result = client.get(f"https://crt.sh/?q=%25.{domain}&output=csv", timeout=30)
    if not result.ok or not result.text.strip():
        return []
    names = set()
    reader = csv.DictReader(io.StringIO(result.text))
    for row in reader:
        for line in (row.get("name_value") or "").split("\n"):
            line = line.strip().lstrip("*.")
            if line:
                names.add(line)
    return sorted(names)


def scrape_shodan(client: HttpClient, domain: str) -> list[str]:
    result = client.get(f"https://www.shodan.io/domain/{domain}", timeout=20)
    if not result.ok or not result.text:
        return []

    soup = BeautifulSoup(result.text, "html.parser")
    container = soup.find("ul", id="subdomains")
    if not container:
        return []

    subs = set()
    for li in container.find_all("li"):
        prefix = li.get_text(strip=True)
        if prefix and prefix != "*":
            subs.add(f"{prefix}.{domain}")
    return sorted(subs)


def merge_sources(domain: str, *sources: list[str]) -> list[str]:
    """Une y deduplica fuentes, descartando hosts ajenos al dominio.

    crt.sh devuelve también los SAN de otros dominios cuando coinciden en
    el certificado; sin este filtro se escanean hosts que no son del target.
    """
    suffix = "." + domain.lower()
    merged: set[str] = set()
    for source in sources:
        for name in source:
            name = name.strip().lower()
            if name == domain.lower() or name.endswith(suffix):
                merged.add(name)
    return sorted(merged)


def check_alive(client: HttpClient, hostnames: list[str], protocol: str,
                 max_workers: int = 20) -> list[str]:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(client.status_only, f"{protocol}://{h}"): h
            for h in hostnames
        }
        for future in as_completed(futures):
            host = futures[future]
            status = future.result()
            if status not in (0, 404):
                alive.append(host)
    return sorted(alive)
