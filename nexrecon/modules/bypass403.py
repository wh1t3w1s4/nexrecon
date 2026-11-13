"""Bypass de 403: variaciones de ruta y cabeceras, probadas en paralelo
con ThreadPoolExecutor en vez del bucle secuencial del bash — con ~14
variaciones por URL y varias URLs con 403, el ahorro de tiempo es real.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from .. import config
from ..http_client import HttpClient

# Cada cabecera de bypass espera un tipo de valor distinto. Antes iban
# todas por el mismo camino y X-Forwarded-Host recibía 127.0.0.1 en vez
# de un hostname.
_IP_HEADERS = {"X-Forwarded-For", "X-Custom-IP-Authorization"}
_HOST_HEADERS = {"X-Forwarded-Host"}
_URL_HEADERS = {"X-Original-URL", "X-Rewrite-URL"}


def _path_variants(path: str) -> list[str]:
    no_lead = path.lstrip("/")
    variants = [f"{path}{suffix}" for suffix in config.BYPASS_403_PATH_SUFFIXES]
    variants += [f"//{no_lead}", f"/./{no_lead}", f"/{no_lead.upper()}"]
    return variants


def test_bypass(client: HttpClient, base_url: str, path: str) -> list[dict]:
    """Devuelve las variaciones que dieron un código distinto de 403/404,
    cada una como {"method": ..., "detail": ..., "status": ...}.
    """
    findings: list[dict] = []
    tasks = []
    hostname = urlparse(base_url).hostname or "127.0.0.1"

    with ThreadPoolExecutor(max_workers=10) as pool:
        for variant in _path_variants(path):
            url = f"{base_url}{variant}"
            tasks.append(pool.submit(
                lambda u=url: (
                    "path",
                    f"variación de ruta: {u}",
                    client.status_only(u, allow_redirects=True),
                )
            ))

        for header_name in config.BYPASS_403_HEADERS:
            if header_name in _IP_HEADERS:
                header_value = "127.0.0.1"
            elif header_name in _HOST_HEADERS:
                header_value = hostname
            elif header_name in _URL_HEADERS:
                header_value = path
            else:
                header_value = f"{base_url}{path}"

            headers = {header_name: header_value}
            url = f"{base_url}{path}"
            tasks.append(pool.submit(
                lambda u=url, h=headers, hn=header_name: (
                    "header",
                    f"header {hn}: {u}",
                    client.status_only(u, headers=h),
                )
            ))

        for future in as_completed(tasks):
            method, detail, status = future.result()
            if status not in (0, 403, 404):
                findings.append({"method": method, "detail": detail, "status": status})

    return findings
