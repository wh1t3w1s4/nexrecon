"""Reconocimiento DNS. Usa dnspython en vez de parsear la salida de texto
de `dig` — resolución directa a la librería de resolución, sin pasar por
subprocess ni parsear stdout, y con anotación automática de patrones
conocidos (SPF/DKIM/DMARC, takeovers, proveedores habituales).
"""
from __future__ import annotations

import dns.query
import dns.resolver
import dns.zone

from ..config import (
    AXFR_TIMEOUT, TXT_PATTERNS, NS_PATTERNS, MX_PATTERNS, CNAME_PATTERNS, CAA_PATTERNS,
)
from ..models import DnsRecordSet

RECORD_TYPES = ["A", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]

_PATTERN_MAP = {
    "TXT": TXT_PATTERNS,
    "NS": NS_PATTERNS,
    "MX": MX_PATTERNS,
    "CNAME": CNAME_PATTERNS,
    "CAA": CAA_PATTERNS,
}


def _annotate(record_type: str, value: str) -> str:
    patterns = _PATTERN_MAP.get(record_type)
    if not patterns:
        return ""
    lowered = value.lower()
    for key, note in patterns.items():
        if lowered.startswith(key) or key in lowered:
            return note
    return ""


def _render_value(record_type: str, rdata) -> str:
    """Normaliza el valor del registro.

    `strip('"')` sobre el texto de un CAA deja la comilla inicial huérfana
    (`0 issue "letsencrypt.org`) porque solo actúa en los extremos. Para
    TXT se unen los trozos entrecomillados, que en un registro SPF largo
    son fragmentos del mismo valor.
    """
    if record_type == "TXT" and getattr(rdata, "strings", None):
        return b"".join(rdata.strings).decode("utf-8", "replace")
    return rdata.to_text()


def query_record(domain: str, record_type: str, timeout: float = 5.0) -> DnsRecordSet:
    result = DnsRecordSet(record_type=record_type)
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=timeout)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return result

    for rdata in answers:
        value = _render_value(record_type, rdata).rstrip(".")
        result.values.append(value)
        note = _annotate(record_type, value)
        if note:
            result.annotations[value] = note
    return result

def full_dns_recon(domain: str, skip_a: bool = False) -> dict[str, DnsRecordSet]:
    """Consulta todos los tipos de registro relevantes. `skip_a=True` si el
    caller ya va a resolver A por separado (para no duplicar la consulta).
    """
    types = [t for t in RECORD_TYPES if not (skip_a and t == "A")]
    return {t: query_record(domain, t) for t in types}


def resolve_a(domain: str, timeout: float = 5.0) -> list[str]:
    rs = query_record(domain, "A", timeout=timeout)
    return rs.values


def attempt_axfr(domain: str, nameservers: list[str],
                  timeout: float = AXFR_TIMEOUT) -> dict[str, list[str]]:
    """Intenta una transferencia de zona (AXFR) contra cada nameserver
    del dominio. Casi siempre falla —es la configuración correcta, un
    servidor DNS bien administrado la rechaza—, así que cualquier
    excepción se interpreta simplemente como "no vulnerable" y se
    descarta en silencio. Cuando SÍ funciona, filtra la zona completa
    de un golpe (todos los subdominios, IPs internas, registros TXT
    internos...), así que merece la pena probarlo siempre: es barato
    (unos pocos segundos por NS) y la señal, cuando aparece, es inequívoca.

    Se usa `except Exception` deliberadamente de forma amplia: dnspython
    puede lanzar desde errores de conexión hasta `TransferError` (la
    respuesta típica de un servidor que rechaza la transferencia), y no
    nos interesa distinguir el motivo — solo si la zona se filtró o no.
    """
    leaks: dict[str, list[str]] = {}

    for ns in nameservers:
        ns_name = ns.rstrip(".")
        try:
            ns_ip = str(dns.resolver.resolve(ns_name, "A", lifetime=timeout)[0])
        except Exception:
            continue

        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(ns_ip, domain, timeout=timeout, lifetime=timeout)
            )
        except Exception:
            continue

        records: list[str] = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    records.append(f"{name}.{domain}. {rdataset.rdtype.name} {rdata.to_text()}")

        if records:
            leaks[ns_name] = records

    return leaks
