"""Integración opcional con nuclei (ProjectDiscovery).

nuclei no tiene un modo "pasivo" propio: cada template manda sus propias
peticiones activas al target (igual que ffuf o wpscan en modo mixed), así
que no se lanza nunca por defecto — solo bajo `--nuclei` o `--deep`, donde
el usuario ya ha aceptado explícitamente más ruido a cambio de más cobertura.

Usamos `-jsonl` (no el `-json` histórico, deprecado) para parsear una
línea = un hallazgo, sin tener que esperar a que todo el escaneo termine
para obtener un único array JSON.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from .. import config
from ..models import Finding, Severity

_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def run_nuclei(url: str, timeout: int = config.NUCLEI_MAX_SECONDS,
               cookie_header: str | None = None) -> list[dict]:
    """Lanza nuclei con su set de templates por defecto (CVEs,
    misconfiguraciones, exposiciones conocidas...) contra `url`.
    Si no está instalado o se agota el tiempo, devuelve lista vacía
    en vez de propagar la excepción — igual que el resto de wrappers
    de herramientas externas del proyecto.
    """
    cmd = ["nuclei", "-u", url, "-jsonl", "-silent", "-no-color"]
    if cookie_header:
        cmd += ["-H", f"Cookie: {cookie_header}"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    raw_results: list[dict] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw_results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return raw_results


def findings_from_nuclei(raw_results: list[dict]) -> list[Finding]:
    """Convierte cada línea JSONL de nuclei en un Finding tipado.
    La severidad de nuclei (info/low/medium/high/critical) coincide
    literalmente con nuestro enum Severity, así que el mapeo es directo.
    """
    findings: list[Finding] = []
    for item in raw_results:
        info = item.get("info", {}) or {}
        severity = _SEVERITY_MAP.get(
            str(info.get("severity", "info")).lower(), Severity.INFO
        )
        name = info.get("name") or item.get("template-id", "nuclei finding")
        matched = item.get("matched-at", item.get("host", ""))
        description = info.get("description", "")

        detail = matched
        if description:
            detail += f" — {description}"

        reference = ""
        refs = info.get("reference")
        if isinstance(refs, list) and refs:
            reference = refs[0]
        elif isinstance(refs, str):
            reference = refs

        findings.append(Finding(
            title=name, severity=severity, detail=detail,
            reference=reference, module="nuclei",
        ))
    return findings
