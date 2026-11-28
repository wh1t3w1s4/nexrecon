"""Integración con searchsploit (exploit-db local, sin red hacia el
target — es una base de datos offline, así que esto corre siempre,
sin gatear tras --deep, a diferencia de nuclei/wpscan-mixed/bypass403).

Filtro de fiabilidad en dos niveles, para no devolver ruido sin más:
  1. CONFIRMADO: búsqueda exacta por CVE, usando los CVEs que VULN_DB
     ya emparejó con la versión detectada (--cve <número>). Esto es
     tan fiable como lo sea VULN_DB — si ya sabemos que la versión es
     vulnerable a ese CVE concreto, cualquier exploit indexado para
     ese mismo CVE aplica directamente.
  2. SIN CONFIRMAR: búsqueda de texto por "tecnología versión" para
     tecnologías que whatweb detectó pero que no están en VULN_DB (o
     que VULN_DB no marcó como vulnerables). Más ruidosa — searchsploit
     empareja por texto del título, no por versión real — se marca
     explícitamente como "revisar manualmente" en el propio hallazgo.

Prioridad: cualquier resultado cuyo título sugiera RCE (ejecución de
código, inyección de comandos, deserialización, LFI-a-RCE, SSTI...) se
marca CRITICAL y sube al principio del listado, por delante de XSS/SQLi/
otros, tal como se pidió explícitamente.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from ..models import SEVERITY_RANK, Confidence, Finding, HostResult, Severity

MODULE_NAME = "searchsploit"
TAG_CONFIRMED = "[CVE confirmado]"
TAG_UNCONFIRMED = "[por tecnología, sin confirmar]"

_RCE_PHRASES = (
    "remote code execution", "code execution", "command injection",
    "arbitrary code", "deserialization", "lfi to rce", "log poisoning",
    "unrestricted file upload", "arbitrary file upload",
    "server-side template injection", "template injection", "ssti",
)
_RCE_WORD_RE = re.compile(r"\brce\b", re.IGNORECASE)

# El instalador oficial de exploit-db (install.sh del repo exploitdb) deja
# searchsploit como un ALIAS de shell, no como un binario real en el PATH —
# por eso `shutil.which` falla aunque "searchsploit" funcione perfectamente
# en la terminal del usuario, sea bash, zsh o cualquier otra. Se añaden las
# rutas de instalación habituales como respaldo, y por si el alias apunta a
# otro sitio, se busca también en los ficheros de configuración de shell
# habituales (bash y zsh, los más comunes; no solo bash). Por último,
# `NEXRECON_SEARCHSPLOIT_PATH` sirve de override explícito para cualquier
# otro caso (otra shell, una ruta atípica...).
_COMMON_PATHS = (
    "/opt/exploitdb/searchsploit",
    "/opt/exploit-database/searchsploit",
    "/usr/share/exploitdb/searchsploit",
    os.path.expanduser("~/exploitdb/searchsploit"),
    os.path.expanduser("~/.exploitdb/searchsploit"),
)
# bash y zsh comparten la sintaxis `alias nombre=valor`; se cubren ambas
# shells (y algunos ficheros menos comunes) sin asumir cuál usa el usuario.
_SHELL_RC_FILES = (
    "~/.zshrc", "~/.bashrc", "~/.bash_aliases", "~/.profile", "~/.zsh_aliases",
)
_ALIAS_RE = re.compile(r"^\s*alias\s+searchsploit\s*=\s*(.+?)\s*$", re.MULTILINE)
_resolved_path: str | None = None
_resolved = False


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return value


def _find_alias_in_shell_rc_files() -> str | None:
    """Busca `alias searchsploit=...` en los ficheros de configuración de
    shell habituales y, si el destino es un ejecutable real, lo devuelve.
    No ejecuta nada de esos ficheros, solo lee texto.
    """
    for rc in _SHELL_RC_FILES:
        path = os.path.expanduser(rc)
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except OSError:
            continue
        match = _ALIAS_RE.search(content)
        if not match:
            continue
        # El valor del alias puede traer flags/argumentos detrás de la ruta
        # (ej. `alias searchsploit="/opt/exploitdb/searchsploit --color"`).
        target = _strip_quotes(match.group(1)).split()[0]
        if os.access(target, os.X_OK):
            return target
    return None


def _resolve_path() -> str | None:
    global _resolved_path, _resolved
    if _resolved:
        return _resolved_path

    candidate = (
        os.environ.get("NEXRECON_SEARCHSPLOIT_PATH")
        or shutil.which("searchsploit")
        or next((p for p in _COMMON_PATHS if os.access(p, os.X_OK)), None)
        or _find_alias_in_shell_rc_files()
    )
    _resolved_path, _resolved = candidate, True
    return candidate


def searchsploit_available() -> bool:
    return _resolve_path() is not None


def _run_json(args: list[str], timeout: int = 30) -> list[dict]:
    binary = _resolve_path()
    if not binary:
        return []
    try:
        proc = subprocess.run(
            [binary, *args, "--json"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        data = json.loads(proc.stdout)
        return data.get("RESULTS_EXPLOIT", [])
    # JSONDecodeError es subclase de ValueError: basta con ValueError.
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        return []


def search_by_term(term: str, timeout: int = 30) -> list[dict]:
    return _run_json([term], timeout=timeout)


def search_by_cve(cve: str, timeout: int = 30) -> list[dict]:
    """`cve` puede venir con o sin el prefijo "CVE-"; searchsploit
    espera el número sin prefijo (ej. "2021-44228"), así que se
    normaliza aquí.
    """
    number = re.sub(r"^CVE-", "", cve.strip(), flags=re.IGNORECASE)
    return _run_json(["--cve", number], timeout=timeout)


def is_rce_likely(title: str) -> bool:
    lower = title.lower()
    if _RCE_WORD_RE.search(lower):
        return True
    return any(phrase in lower for phrase in _RCE_PHRASES)


def classify_severity(title: str, exploit_type: str) -> Severity:
    if is_rce_likely(title):
        return Severity.CRITICAL
    t = (exploit_type or "").lower()
    if t in ("remote", "webapps"):
        return Severity.HIGH
    return Severity.MEDIUM  # local, dos, shellcode, papers...


def _build_finding(result: dict, confirmed: bool, source_cve: str | None) -> Finding:
    title = result.get("Title", "sin título")
    edb_id = result.get("EDB-ID", "?")
    exploit_type = result.get("Type", "")
    severity = classify_severity(title, exploit_type)

    tag = TAG_CONFIRMED if confirmed else TAG_UNCONFIRMED
    # CONFIRMADO: tan fiable como VULN_DB (aún con sus caveats de fingerprinting
    # HTTP, por eso FIRM y no CERTAIN). SIN CONFIRMAR: empareja por texto del
    # título contra la tecnología detectada, no por versión real — mucho más
    # ruidoso, de ahí TENTATIVE (antes ambos caían en el mismo FIRM por defecto,
    # sin que el grado de confianza reflejara esa diferencia ya documentada).
    confidence = Confidence.FIRM if confirmed else Confidence.TENTATIVE
    detail_parts = [f"EDB-ID {edb_id}", f"tipo: {exploit_type or 'desconocido'}"]
    if source_cve:
        detail_parts.append(f"vía {source_cve}")
    detail_parts.append(f"https://www.exploit-db.com/exploits/{edb_id}")

    return Finding(
        title=f"{tag} Exploit público: {title}",
        severity=severity,
        detail=", ".join(detail_parts),
        module=MODULE_NAME,
        confidence=confidence,
    )


def gather_exploits_for_host(host: HostResult) -> list[Finding]:
    if not searchsploit_available():
        return [Finding(
            title="searchsploit no está instalado, se omite", severity=Severity.INFO,
            detail="Instálalo con: sudo apt install exploitdb. Si ya lo tienes pero sigue "
                   "sin encontrarse (p. ej. está configurado como alias de shell), define "
                   "NEXRECON_SEARCHSPLOIT_PATH con la ruta completa al binario.",
            module=MODULE_NAME,
        )]

    seen_ids: set[str] = set()
    findings: list[Finding] = []

    # Nivel 1 — confirmado: un CVE por el que VULN_DB ya marcó la
    # versión detectada como vulnerable.
    for vuln in host.vulns:
        for cve in vuln.cve.split(","):
            cve = cve.strip()
            if not cve.upper().startswith("CVE-"):
                continue
            for result in search_by_cve(cve):
                edb_id = result.get("EDB-ID", "")
                if not edb_id or edb_id in seen_ids:
                    continue
                seen_ids.add(edb_id)
                findings.append(_build_finding(result, confirmed=True, source_cve=cve))

    # Nivel 2 — sin confirmar: tecnología + versión, texto libre.
    for tech, version in host.technologies.items():
        if not version:
            continue
        for result in search_by_term(f"{tech} {version}"):
            edb_id = result.get("EDB-ID", "")
            if not edb_id or edb_id in seen_ids:
                continue
            seen_ids.add(edb_id)
            findings.append(_build_finding(result, confirmed=False, source_cve=None))

    findings.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 9))
    return findings


def count_exploits(host: HostResult) -> tuple[int, int]:
    """(confirmados, total) de exploits de searchsploit en un host.

    Excluye los avisos INFO ("searchsploit no está instalado"), que
    comparten módulo pero no son un exploit. Pensado para la tabla de
    postura: se muestra aparte de `host.vulns` porque los exploits
    confirmados parten de los mismos CVEs que ya cuenta VULN_DB y
    sumarlos en la misma cifra los contaría dos veces.
    """
    total = confirmed = 0
    for finding in host.findings:
        if finding.module != MODULE_NAME or finding.severity is Severity.INFO:
            continue
        total += 1
        if finding.title.startswith(TAG_CONFIRMED):
            confirmed += 1
    return confirmed, total
