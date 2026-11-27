"""Contexto de recon autenticado (--cookie).

La sola presencia de `--cookie` activa el modo; no hay flag booleano aparte.

Reglas de seguridad (el valor de la cookie es una sesión viva):
- Solo se envía al dominio objetivo y sus subdominios (nunca a crt.sh,
  Shodan, ipinfo u otros terceros que usa el mismo HttpClient).
- Nunca se escribe en los reportes: solo los NOMBRES de las cookies.
  `redact()` es una segunda red por si algún valor se cuela en texto
  libre (salida de una herramienta externa, un Set-Cookie que la
  reemplaza, etc.).
"""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field

REDACTED = "[REDACTED]"
# Por debajo de esta longitud no se hace sustitución global en texto libre:
# un valor de 1-3 caracteres ("1", "en") corrompería el reporte entero.
_MIN_SCRUB_LEN = 4
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def parse_cookie_header(raw: str) -> dict[str, str]:
    """`"A=1; B=2"` -> {"A": "1", "B": "2"}. Lanza ValueError si es inválida."""
    if _CONTROL_CHARS.search(raw):
        raise ValueError("la cookie contiene caracteres de control")
    cookies: dict[str, str] = {}
    for chunk in raw.split(";"):
        part = chunk.strip()
        if not part:
            continue
        name, sep, value = part.partition("=")
        name = name.strip()
        if not sep or not name:
            raise ValueError(f"formato inválido cerca de {name or part!r}: se esperaba nombre=valor")
        cookies[name] = value.strip()
    if not cookies:
        raise ValueError("no se encontró ninguna cookie")
    return cookies


def argparse_cookie(raw: str) -> AuthContext:
    """`type=` para argparse."""
    try:
        return AuthContext(parse_cookie_header(raw))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


@dataclass(frozen=True)
class AuthContext:
    cookies: dict[str, str] = field(repr=False)  # repr=False: no filtrar valores en logs/tracebacks

    @property
    def names(self) -> list[str]:
        return list(self.cookies)

    @property
    def header(self) -> str:
        """Valor de la cabecera `Cookie:` (para binarios externos)."""
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def secrets(self) -> list[str]:
        return [v for v in self.cookies.values() if len(v) >= _MIN_SCRUB_LEN]

    def redact(self, text: str) -> str:
        return redact_text(text, self.secrets())

    def redact_set_cookie(self, raw: str) -> str:
        """Si un `Set-Cookie` devuelve el valor de una cookie nuestra
        (p. ej. el servidor refresca PHPSESSID), se oculta el valor."""
        name, sep, _ = raw.partition(";")[0].partition("=")
        if sep and name.strip() in self.cookies:
            rest = raw.partition(";")[2]
            return f"{name.strip()}={REDACTED}" + (f";{rest}" if rest else "")
        return raw


def redact_text(text: str, secrets: list[str]) -> str:
    # Más largos primero: si un valor contiene a otro, no queda un resto.
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    return text
