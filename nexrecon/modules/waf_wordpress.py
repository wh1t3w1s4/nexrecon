"""Wrappers de wafw00f y wpscan. Ambos son motores de detección
especializados (firmas de decenas de WAFs, base de datos de plugins
vulnerables de WordPress) — se invocan vía subprocess y se parsea su
salida a estructuras simples.
"""
from __future__ import annotations

import re
import shutil
import subprocess

from .. import config

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def detect_waf(url: str) -> str | None:
    try:
        proc = subprocess.run(
            ["wafw00f", "-c", url], capture_output=True, text=True, timeout=30
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


def run_wpscan(url: str, timeout: int = config.WPSCAN_TIMEOUT_DEFAULT,
               mode: str = config.WPSCAN_MODE_DEFAULT) -> dict:
    """`mode="passive"` (por defecto) detecta solo por rastro en el HTML,
    segundos. `mode="mixed"` añade barrido activo de slugs conocidos —
    minutos, y solo tiene sentido bajo --deep, con timeout más holgado.

    Devuelve siempre un dict con tres claves para que el caller nunca
    tenga que adivinar por qué "raw" está vacío:
      - "raw": salida filtrada (string, puede ser "")
      - "timed_out": True si se agotó el tiempo
      - "error": motivo legible si algo falló (proceso no encontrado,
        código de salida distinto de 0 con stdout vacío, etc.), o "" si
        todo fue normal. Antes esto se perdía en silencio — un wpscan
        que fallaba por red o por un flag mal aceptado quedaba
        indistinguible de "wpscan corrió bien y no encontró nada".
    """
    args = [
        "wpscan", "--url", url, "--random-user-agent",
        "-e", "vp,vt,u1-5", "--detection-mode", mode,
        "--disable-tls-checks",
    ]
    if config.WPSCAN_API_TOKEN:
        args += ["--api-token", config.WPSCAN_API_TOKEN]

    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"timed_out": True, "raw": "", "error": ""}
    except FileNotFoundError:
        return {"timed_out": False, "raw": "", "error": "wpscan no está instalado o no está en el PATH"}

    skip_patterns = (
        "Requests Done", "Cached Requests", "Data Sent",
        "Data Received", "Memory used", "Elapsed time",
    )
    lines = [
        line for line in proc.stdout.splitlines()
        if not any(p in line for p in skip_patterns)
    ]
    raw = "\n".join(lines).strip()

    error = ""
    if not raw and proc.returncode != 0:
        stderr_tail = (proc.stderr or "").strip().splitlines()
        error = stderr_tail[-1] if stderr_tail else f"wpscan terminó con código {proc.returncode}"

    return {"timed_out": False, "raw": raw, "error": error}
