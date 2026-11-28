"""Enriquecimiento de vulnerabilidades vía OSV.dev (Open Source Vulnerabilities).

VULN_DB (en `config.py`) es una lista estática de 17 entradas, mantenida a
mano. OSV.dev tiene cobertura muchísimo mayor, pero empareja por
`(ecosistema, paquete, versión)`, no por texto libre — así que no sirve de
sustituto directo: es excelente para librerías JS (npm: jQuery, Bootstrap,
Lodash... justo lo que whatweb/endpoint_discovery detectan) y paquetes de
lenguaje, pero pobre o dependiente de la distro para nginx/Apache/PHP-core,
que no tienen un "paquete" claro en ningún ecosistema de OSV.

Por eso: **OSV aumenta a VULN_DB, no lo reemplaza.** Solo se consulta para
tecnologías con una entrada en `config.OSV_ECOSYSTEM_MAP`; el resto sigue
dependiendo exclusivamente de VULN_DB, igual que antes de esta feature.

Sin tráfico adicional de riesgo: es una consulta a una API pública de
terceros (api.osv.dev), nunca al target, y nunca lleva la cookie de sesión
(`HttpClient` ya la acota a `scope_domain` — no hay nada que evitar aquí).
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass

from .. import config
from ..http_client import HttpClient
from ..models import Confidence, HostResult, Severity, VulnMatch
from .vuln_db import _clean_version

MODULE_NAME = "osv"

_cache: dict[tuple[str, str, str], list[OsvVuln]] = {}
_cache_lock = threading.Lock()


@dataclass
class OsvVuln:
    id: str              # GHSA-... o CVE-...
    cve: str             # mejor CVE de los aliases, o `id` si no hay ninguno
    summary: str
    fixed_in: str        # primera versión "fixed" vista en los rangos, o ""
    cvss: str            # vector/score si viene, o ""
    reference: str


def _best_cve(vuln: dict) -> str:
    for alias in vuln.get("aliases", []):
        if alias.upper().startswith("CVE-"):
            return alias
    vid = vuln.get("id", "")
    return vid if vid.upper().startswith("CVE-") else vid


def _first_fixed_version(vuln: dict) -> str:
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return ""


def _first_cvss(vuln: dict) -> str:
    for sev in vuln.get("severity", []):
        score = sev.get("score")
        if score:
            return score
    return ""


def _first_reference(vuln: dict) -> str:
    refs = vuln.get("references", [])
    for ref in refs:
        url = ref.get("url", "")
        if "nvd.nist.gov" in url or "github.com/advisories" in url:
            return url
    return refs[0]["url"] if refs and refs[0].get("url") else ""


def _parse_osv_vuln(raw: dict) -> OsvVuln:
    summary = raw.get("summary") or (raw.get("details") or "")[:300]
    return OsvVuln(
        id=raw.get("id", ""),
        cve=_best_cve(raw),
        summary=summary,
        fixed_in=_first_fixed_version(raw),
        cvss=_first_cvss(raw),
        reference=_first_reference(raw),
    )


def query_osv(client: HttpClient, ecosystem: str, package: str, version: str,
              timeout: int = config.OSV_TIMEOUT) -> list[OsvVuln]:
    """Consulta OSV.dev para `(ecosystem, package, version)`. OSV hace el
    emparejamiento de rangos en su lado — cada objeto en `vulns[]` ya
    APLICA a esta versión concreta, no hace falta comparar versiones aquí.

    Cualquier fallo (red, no-200, JSON inesperado) devuelve lista vacía:
    es un enriquecimiento opcional, nunca debe tumbar el escaneo.
    """
    try:
        res = client.request(
            "POST", config.OSV_API_URL,
            json_body={"version": version, "package": {"name": package, "ecosystem": ecosystem}},
            timeout=timeout,
        )
        if not res.ok or res.status_code != 200:
            return []
        data = json.loads(res.text)
        return [_parse_osv_vuln(v) for v in data.get("vulns", []) if isinstance(v, dict)]
    except Exception:
        return []


def _cached_query(client: HttpClient, ecosystem: str, package: str, version: str) -> list[OsvVuln]:
    key = (ecosystem, package, version)
    with _cache_lock:
        if key in _cache:
            return _cache[key]
    # La consulta de red se hace FUERA del lock: varias peticiones a OSV en
    # paralelo (root + subdominios con la misma librería) no se bloquean
    # entre sí; solo se compite por escribir en el cache al final.
    result = query_osv(client, ecosystem, package, version)
    with _cache_lock:
        _cache.setdefault(key, result)
    return _cache[key]


def enrich(client: HttpClient, host: HostResult, static_cves: set[str]) -> list[VulnMatch]:
    """Devuelve `VulnMatch` nuevos (no ya cubiertos por `static_cves`, los
    CVEs que VULN_DB ya emparejó) y añade el `Finding` correspondiente.
    """
    matches: list[VulnMatch] = []

    for tech, raw_version in host.technologies.items():
        mapping = config.OSV_ECOSYSTEM_MAP.get(tech.lower())
        if not mapping:
            continue
        version = _clean_version(raw_version)
        if not version:
            continue
        ecosystem, package = mapping

        for vuln in _cached_query(client, ecosystem, package, version):
            if vuln.cve and vuln.cve in static_cves:
                continue  # ya lo tiene VULN_DB, no duplicar
            match = VulnMatch(
                technology=tech, detected_version=version,
                fixed_in=vuln.fixed_in or "desconocida", cve=vuln.cve,
                description=vuln.summary, reference=vuln.reference,
                source="osv", confidence=Confidence.FIRM, cvss=vuln.cvss,
            )
            matches.append(match)
            cvss_note = f" (CVSS: {vuln.cvss})" if vuln.cvss else ""
            host.add_finding(
                f"{tech} {version} vulnerable según OSV.dev ({vuln.id})",
                Severity.HIGH,
                f"{vuln.cve or vuln.id}{cvss_note} — {vuln.summary}. Nota: la versión se "
                "detecta por fingerprinting HTTP (whatweb); si hay un WAF/CDN delante del "
                "origen real, puede corresponder al proxy y no al servidor efectivo — "
                "confirma antes de dar esto por explotable.",
                reference=vuln.reference,
                module=MODULE_NAME,
                confidence=Confidence.FIRM,
            )

    return matches
