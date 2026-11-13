"""Fingerprinting vía whatweb (subprocess). Reimplementar un motor de
fingerprinting con firmas de cientos de tecnologías no tiene sentido;
el valor está en parsear su salida a estructuras tipadas y detectar
bloqueos de Cloudflare automáticamente, igual que hacía el bash pero
sin los greps frágiles sobre texto con color ANSI.
"""
from __future__ import annotations

import re
import subprocess

PLUGIN_RE = re.compile(r"^\[ (.+) \]$")
VERSION_RE = re.compile(r"Version\s*:\s*([^\s(]+)")


def run_whatweb(url: str) -> str:
    try:
        proc = subprocess.run(
            ["whatweb", "-v", "--color=never", url],
            capture_output=True, text=True, timeout=30,
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def is_cloudflare_block(whatweb_output: str) -> bool:
    lower = whatweb_output.lower()
    return "cloudflare" in lower and (
        "403 forbidden" in lower or "just a moment" in lower
    )


def extract_technologies(whatweb_output: str) -> dict[str, str]:
    """Devuelve {tecnología: versión}. La versión puede ser cadena vacía.

    Antes solo se guardaban los plugins con versión, así que un host con
    nginx y PHP sin versión se quedaba con el diccionario vacío y sin
    fingerprint en el informe.
    """
    techs: dict[str, str] = {}
    current_plugin = None
    for line in whatweb_output.splitlines():
        plugin_match = PLUGIN_RE.match(line.strip())
        if plugin_match:
            current_plugin = plugin_match.group(1)
            techs.setdefault(current_plugin, "")
            continue
        version_match = VERSION_RE.search(line)
        if version_match and current_plugin:
            techs[current_plugin] = version_match.group(1)
    return techs
