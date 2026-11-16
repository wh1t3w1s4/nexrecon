"""Cruce de tecnologías/versiones detectadas contra VULN_DB.

Usa `packaging.version` para comparar versiones correctamente (2.4.9 <
2.4.10, por ejemplo) en vez del hack de `sort -V` que usábamos en bash,
que puede fallar con formatos de versión no estándar.
"""
from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

from ..config import VULN_DB
from ..models import HostResult, Severity, VulnMatch


def _clean_version(raw: str) -> str | None:
    match = re.match(r"^[0-9]+(\.[0-9]+)*", raw.strip())
    return match.group(0) if match else None


def check_technologies(host: HostResult) -> list[VulnMatch]:
    matches: list[VulnMatch] = []

    for tech, detected_raw in host.technologies.items():
        version_str = _clean_version(detected_raw)
        if not version_str:
            continue
        try:
            detected = Version(version_str)
        except InvalidVersion:
            continue

        for entry in VULN_DB:
            if entry.technology.lower() != tech.lower():
                continue
            if entry.branch_prefix and not version_str.startswith(entry.branch_prefix):
                continue
            try:
                fixed = Version(entry.fixed_in)
            except InvalidVersion:
                continue

            if detected < fixed:
                match = VulnMatch(
                    technology=tech, detected_version=version_str,
                    fixed_in=entry.fixed_in, cve=entry.cve,
                    description=entry.description, reference=entry.reference,
                )
                matches.append(match)
                host.add_finding(
                    f"{tech} {version_str} vulnerable (< {entry.fixed_in})",
                    Severity.HIGH,
                    f"{entry.cve} — {entry.description}. Nota: la versión se "
                    "detecta por fingerprinting HTTP (whatweb); si hay un "
                    "WAF/CDN delante del origen real, puede corresponder al "
                    "proxy y no al servidor efectivo — confirma antes de dar "
                    "esto por explotable.",
                    reference=entry.reference,
                    module="vuln_db",
                )

    return matches
