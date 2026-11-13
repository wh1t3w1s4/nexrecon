"""Modelos de datos centrales de Web-Recon.

Sustituyen al patrón "string1|string2|string3" + IFS read que usábamos
en bash para simular estructuras. Aquí son objetos reales, serializables
a JSON sin esfuerzo (dataclasses.asdict) y con autocompletado en cualquier
editor, lo que elimina de raíz toda la clase de bugs de "me comí un campo
al hacer IFS='|' read".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Orden real de gravedad. El valor del enum ordena alfabéticamente
# (critical, high, info, low, medium), que no sirve para priorizar.
SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Finding:
    """Un hallazgo individual: una vulnerabilidad, una mala configuración,
    un dato interesante. Todo lo que antes era un `echo "[!] ..."` suelto
    en el bash ahora es un objeto con severidad, lo que permite ordenar,
    filtrar y puntuar sin parsear texto.
    """
    title: str
    severity: Severity
    detail: str = ""
    reference: str = ""
    module: str = ""  # qué módulo lo generó (whatweb, cookies, waf...)


@dataclass
class Cookie:
    name: str
    raw: str
    http_only: bool = False
    secure: bool = False
    same_site: Optional[str] = None

    @property
    def is_fully_protected(self) -> bool:
        return self.http_only and self.secure and self.same_site is not None

    @property
    def has_no_protection(self) -> bool:
        return not self.http_only and not self.secure and self.same_site is None


@dataclass
class DnsRecordSet:
    record_type: str
    values: list[str] = field(default_factory=list)
    annotations: dict[str, str] = field(default_factory=dict)  # valor -> nota


@dataclass
class IpIntel:
    ip: str
    ipinfo_summary: str = ""
    shodan_ports: list[int] = field(default_factory=list)
    shodan_hostnames: list[str] = field(default_factory=list)
    shodan_cves: list[str] = field(default_factory=list)
    shodan_tags: list[str] = field(default_factory=list)


@dataclass
class VulnMatch:
    technology: str
    detected_version: str
    fixed_in: str
    cve: str
    description: str
    reference: str


@dataclass
class DirectoryHit:
    url: str
    status: int
    words: int
    lines: int
    is_noise_pattern: bool = False


@dataclass
class HostResult:
    """Todo lo que sabemos de un host concreto (el raíz o un
    subdominio). Es la unidad que luego se compara en la fase de
    postura de seguridad, y la unidad que se serializa a JSON/Markdown.
    """
    hostname: str
    protocol: Optional[str] = None
    technologies: dict[str, str] = field(default_factory=dict)  # nombre -> version
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[Cookie] = field(default_factory=list)
    waf: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)
    vulns: list[VulnMatch] = field(default_factory=list)
    score_breakdown: list[tuple[str, int]] = field(default_factory=list)
    directories_clean: list[DirectoryHit] = field(default_factory=list)
    directories_suspicious: list[DirectoryHit] = field(default_factory=list)
    forbidden_bypassed: list[dict] = field(default_factory=list)
    wordpress: Optional[dict] = None
    score: int = 60

    def add_finding(self, title: str, severity: Severity, detail: str = "",
                     reference: str = "", module: str = "") -> None:
        self.findings.append(Finding(title, severity, detail, reference, module))

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]


@dataclass
class ScanResult:
    """Objeto raíz de todo el escaneo. Un único árbol serializable que
    contiene Fase 1, Fase 2, descubrimiento de subdominios y comparación
    de postura — en bash esto estaba repartido en 15 variables sueltas.
    """
    target: str
    mode: str  # "full" o "subdomain"
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str] = None
    whois_raw: str = ""
    dns_records: dict[str, DnsRecordSet] = field(default_factory=dict)
    ip_addresses: list[str] = field(default_factory=list)
    ip_intel: list[IpIntel] = field(default_factory=list)
    hosts: dict[str, HostResult] = field(default_factory=dict)
    subdomain_sources: dict[str, list[str]] = field(default_factory=dict)
    subdomains_merged: list[str] = field(default_factory=list)
    subdomains_alive: list[str] = field(default_factory=list)
    robots_paths: list[str] = field(default_factory=list)
    axfr_attempted: bool = False
    axfr_results: dict[str, list[str]] = field(default_factory=dict)

    def get_or_create_host(self, hostname: str) -> HostResult:
        if hostname not in self.hosts:
            self.hosts[hostname] = HostResult(hostname=hostname)
        return self.hosts[hostname]

    def finish(self) -> None:
        self.finished_at = datetime.now(timezone.utc).isoformat()
