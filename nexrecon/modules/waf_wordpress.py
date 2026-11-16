"""Wrappers de wafw00f y wpscan. Ambos son motores de detección
especializados (firmas de decenas de WAFs, base de datos de plugins
vulnerables de WordPress) — se invocan vía subprocess y se parsea su
salida a estructuras simples.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
from typing import Callable

from .. import config

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def detect_waf(url: str) -> str | None:
    """OJO: wafw00f NO tiene flag -c (no existe "forzar color" en su
    CLI real: -h -v -a -r -t -o -f -i -l -V son las únicas opciones).
    Pasarle un flag inválido hace que falle antes de escanear nada y
    nunca llega a imprimir "is behind X WAF" — exactamente el bug que
    hacía que WAFs reales (Cloudflare, confirmado a mano) salieran como
    "no detectado". Se invoca sin flags extra, solo la URL.
    """
    try:
        proc = subprocess.run(
            ["wafw00f", url], capture_output=True, text=True, timeout=30
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    clean = _ANSI_RE.sub("", proc.stdout)
    match = re.search(r"is behind (.+?) WAF", clean)
    return match.group(1).strip() if match else None


def is_wordpress(whatweb_output: str) -> bool:
    return "wordpress" in whatweb_output.lower()


def wpscan_available() -> bool:
    return shutil.which("wpscan") is not None


def update_wpscan_db(timeout: int = 60) -> dict:
    """`wpscan --update`. Se recomienda lanzarlo cada vez que se detecta
    WordPress, antes del escaneo — si la BD lleva tiempo sin actualizar,
    wpscan avisa pero sigue funcionando con datos parcialmente obsoletos.
    No es fatal si falla (sin red, timeout, etc.): se informa y se sigue
    con el escaneo igualmente, con la BD que hubiera.
    """
    args = ["wpscan", "--update"]
    if config.WPSCAN_API_TOKEN:
        args += ["--api-token", config.WPSCAN_API_TOKEN]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return {"ok": proc.returncode == 0, "output": proc.stdout.strip()}
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": f"timeout a los {timeout}s"}
    except FileNotFoundError:
        return {"ok": False, "output": "wpscan no está instalado"}


def run_wpscan(url: str, timeout: int = config.WPSCAN_TIMEOUT_DEFAULT,
               mode: str = config.WPSCAN_MODE_DEFAULT,
               on_line: Callable[[str], None] | None = None) -> dict:
    """`mode="passive"` (por defecto) detecta solo por rastro en el HTML,
    segundos. `mode="mixed"` añade barrido activo de slugs conocidos —
    minutos, y solo tiene sentido bajo --deep, con timeout más holgado.

    `on_line`, si se pasa, recibe cada línea de salida EN TIEMPO REAL
    (vía subprocess.Popen, no subprocess.run) — así se puede mostrar
    progreso real ("Enumerating Users...", "XML-RPC seems to be
    enabled") en vez de un spinner ciego, y saber exactamente en qué
    paso se queda si tarda o falla. stderr se combina con stdout para
    poder verlo también en el stream (a cambio de perder la separación
    fina entre ambos que teníamos con subprocess.run).

    Devuelve siempre un dict con estas claves para que el caller nunca
    tenga que adivinar por qué "raw" está vacío:
      - "raw": salida filtrada (string, puede ser "")
      - "lines": lista de líneas crudas (para clasificar hallazgos)
      - "timed_out": True si se agotó el tiempo
      - "error": motivo legible si algo falló, o "" si todo fue normal
      - "db_outdated": True si wpscan avisó de que su BD lleva tiempo
        sin actualizar (no es un fallo, solo una recomendación)
    """
    args = [
        "wpscan", "--url", url, "--random-user-agent",
        "-e", "vp,vt,u1-5", "--detection-mode", mode,
        "--disable-tls-checks",
    ]
    if config.WPSCAN_API_TOKEN:
        args += ["--api-token", config.WPSCAN_API_TOKEN]

    try:
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except FileNotFoundError:
        return {"timed_out": False, "raw": "", "lines": [], "error":
                "wpscan no está instalado o no está en el PATH", "db_outdated": False}

    lines: list[str] = []
    start = time.monotonic()
    timed_out = False

    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            line = line.rstrip("\n")
            lines.append(line)
            if on_line:
                on_line(line)
            if time.monotonic() - start > timeout:
                timed_out = True
                proc.kill()
                break
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
        timed_out = timed_out or (time.monotonic() - start > timeout)

    if timed_out:
        return {"timed_out": True, "raw": "", "lines": lines, "error": "", "db_outdated": False}

    full_output = "\n".join(lines)
    skip_patterns = (
        "Requests Done", "Cached Requests", "Data Sent",
        "Data Received", "Memory used", "Elapsed time",
    )
    filtered = [l for l in lines if not any(p in l for p in skip_patterns)]
    raw = "\n".join(filtered).strip()

    error = ""
    if not raw and proc.returncode not in (0, None):
        error = f"wpscan terminó con código {proc.returncode}"

    db_outdated = "have not updated the database" in full_output.lower()

    return {"timed_out": False, "raw": raw, "lines": lines, "error": error, "db_outdated": db_outdated}


def extract_wordpress_findings(lines: list[str]) -> list[dict]:
    """Clasifica líneas de wpscan en hallazgos estructurados: usuarios
    enumerados y posibles backups de configuración expuestos.

    Esto es coincidencia por palabras clave sobre el formato de salida
    habitual de wpscan, no un parser oficial de su estructura interna
    — el formato puede variar ligeramente entre versiones. Si no
    detecta nada pero sabes que wpscan sí encontró usuarios/backups,
    revisa el .md completo (ahí siempre está la salida íntegra) y
    avísame para ajustar los patrones.
    """
    findings: list[dict] = []
    in_users_block = False

    for line in lines:
        stripped = line.strip()
        lower = stripped.lower()

        if stripped.startswith("[i] User(s) Identified"):
            in_users_block = True
            continue

        if in_users_block:
            match = re.match(r"^\[\+\]\s+(\S+)$", stripped)
            if match:
                findings.append({
                    "kind": "user", "severity": "medium",
                    "title": f"Usuario de WordPress identificado: {match.group(1)}",
                    "detail": "Usuario enumerado por wpscan — facilita ataques de "
                              "fuerza bruta/credential stuffing dirigidos.",
                })
                continue
            # Las líneas en blanco y las de metadata (" | Found By: ...")
            # son normales DENTRO del bloque de usuarios — solo salimos
            # al llegar a la siguiente fase de enumeración, nunca por un
            # simple salto de línea entre un usuario y el siguiente.
            if stripped.startswith("[+] Enumerating") or stripped.startswith("[i] No"):
                in_users_block = False

        if ("xml-rpc" in lower or "xmlrpc.php" in lower) and ("enabled" in lower or "identified" in lower):
            findings.append({
                "kind": "xmlrpc", "severity": "low",
                "title": "XML-RPC habilitado (xmlrpc.php)",
                "detail": stripped + " — amplifica fuerza bruta vía system.multicall "
                          "y puede usarse para SSRF vía pingback.",
            })

        if (("backup" in lower or "wp-config" in lower or ".sql" in lower)
                and ("identified" in lower or "found" in lower)):
            findings.append({
                "kind": "config_backup", "severity": "critical",
                "title": "Posible backup de configuración expuesto",
                "detail": stripped,
            })

    return findings
