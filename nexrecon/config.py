"""Configuración centralizada: rutas, umbrales, listas de User-Agents y
la base de datos de vulnerabilidades por versión (equivalente a VULN_DB
en el bash, pero como objetos tipados en vez de strings separados por '|').
"""
from __future__ import annotations

import os
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Rutas y binarios externos (se siguen usando herramientas especializadas
# vía subprocess: no tiene sentido reimplementar ffuf, subfinder, whatweb,
# wafw00f o wpscan en Python, son motores maduros con años de desarrollo).
# ---------------------------------------------------------------------------
# Wordlist ligera por defecto: suficiente para CTFs típicos (HTB,
# PortSwigger, Hacker101) sin pagar el coste en tiempo de las ~20k
# líneas de big.txt, que queda reservada al modo --deep.
WORDLIST_DEFAULT = os.environ.get(
    "NEXRECON_WORDLIST", "/usr/share/seclists/Discovery/Web-Content/common.txt"
)
WORDLIST_DEEP = os.environ.get(
    "NEXRECON_WORDLIST_DEEP", "/usr/share/dirb/wordlists/big.txt"
)
HTTPX_BIN = os.environ.get("HTTPX_BIN", os.path.expanduser("~/.go/bin/httpx"))
WPSCAN_API_TOKEN = os.environ.get("WPSCAN_API_TOKEN", "")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")

DEFAULT_OUTPUT_DIR = "resultados"
MAX_IPS_TO_ANALYZE = 4
NOISE_THRESHOLD = 5          # mismo status/words/lines repetido > N veces -> ruido
RATE_LIMIT_THRESHOLD = 10    # nº de códigos de bloqueo antes de bajar hilos de ffuf
# 500/502/504 se incluyen junto a 429/503/508: varios WAFs y servidores
# bajo presión responden con un 500 genérico en vez de un 429/503 "limpio"
# cuando están limitando — si no se detecta esto, el throttle nunca se
# dispara y el escaneo entero puede degradar en ruido silenciosamente.
RATE_LIMIT_STATUS_CODES = frozenset({429, 500, 502, 503, 504, 508})
FFUF_THREADS_DEFAULT = 40    # más conservador y sigiloso que 80; sube con --deep si hace falta
FFUF_THREADS_THROTTLED = 20
FFUF_MAX_SECONDS = int(os.environ.get("NEXRECON_FFUF_MAX_SECONDS", "120"))
FFUF_MAX_SECONDS_DEEP = int(os.environ.get("NEXRECON_FFUF_MAX_SECONDS_DEEP", "300"))
HTTP_TIMEOUT = 10
POSTURE_GAP_ALERT = 30       # diferencia de score que dispara el aviso de "eslabón débil"

# wpscan: pasivo por defecto (segundos, no minutos); modo "mixed" (barrido
# activo de slugs) solo bajo --deep, con más margen de tiempo.
WPSCAN_MODE_DEFAULT = "passive"
WPSCAN_MODE_DEEP = "mixed"
WPSCAN_TIMEOUT_DEFAULT = 90   # pasivo debería terminar en segundos; 180s ocultaba timeouts silenciosos
WPSCAN_TIMEOUT_DEEP = 400

# nuclei: sin modo pasivo propio (cada template manda peticiones activas),
# por eso solo se lanza bajo --nuclei o --deep, nunca por defecto.
NUCLEI_MAX_SECONDS = int(os.environ.get("NEXRECON_NUCLEI_MAX_SECONDS", "300"))

# AXFR: timeout corto, ya que casi siempre falla (es lo esperado) y no
# tiene sentido esperar mucho por un nameserver bien configurado.
AXFR_TIMEOUT = float(os.environ.get("NEXRECON_AXFR_TIMEOUT", "10"))

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


@dataclass(frozen=True)
class VulnEntry:
    technology: str
    fixed_in: str          # versión en la que se corrigió (vulnerable si detectada < esta)
    branch_prefix: str      # "" si aplica a todas las ramas, p.ej. "3." para Bootstrap 3.x
    cve: str
    description: str
    reference: str


VULN_DB: list[VulnEntry] = [
    VulnEntry("jQuery", "3.5.0", "", "CVE-2020-11022,CVE-2020-11023",
              "XSS al pasar HTML no confiable a métodos como .html()/.append()",
              "https://nvd.nist.gov/vuln/detail/CVE-2020-11022"),
    VulnEntry("jQuery", "1.9.0", "", "CVE-2015-9251",
              "XSS en respuestas Ajax con Content-Type incorrecto",
              "https://nvd.nist.gov/vuln/detail/CVE-2015-9251"),
    VulnEntry("Bootstrap", "3.4.1", "3.", "CVE-2018-14040,CVE-2018-14041,CVE-2018-14042",
              "XSS en plugins tooltip/affix/collapse (rama 3.x)",
              "https://nvd.nist.gov/vuln/detail/CVE-2018-14042"),
    VulnEntry("Bootstrap", "4.3.1", "4.", "CVE-2019-8331",
              "XSS en tooltip/popover vía atributo data-template (rama 4.x)",
              "https://nvd.nist.gov/vuln/detail/CVE-2019-8331"),
    VulnEntry("nginx", "1.20.1", "", "CVE-2021-23017",
              "Desbordamiento de búfer en el resolver DNS interno",
              "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"),
    VulnEntry("Apache", "2.4.51", "", "CVE-2021-41773,CVE-2021-42013",
              "Path traversal / RCE en mod_cgi (versiones 2.4.49-2.4.50)",
              "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"),
    VulnEntry("Lodash", "4.17.21", "", "CVE-2020-8203,CVE-2019-10744",
              "Prototype Pollution",
              "https://nvd.nist.gov/vuln/detail/CVE-2020-8203"),
    VulnEntry("OpenSSL", "1.0.1g", "", "CVE-2014-0160",
              "Heartbleed — fuga de memoria del proceso",
              "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"),
    VulnEntry("PHP", "5.6.40", "", "CVE-2019-11043",
              "RCE en php-fpm bajo nginx con rutas concretas",
              "https://nvd.nist.gov/vuln/detail/CVE-2019-11043"),
]


# Anotaciones de registros DNS (equivalente a interpretar_registro en bash)
TXT_PATTERNS = {
    "v=spf1": "SPF — define qué servidores pueden enviar correo en nombre del dominio",
    "v=dkim1": "DKIM — firma criptográfica de autenticidad de correo",
    "v=dmarc1": "DMARC — política de qué hacer si el correo falla SPF/DKIM",
    "google-site-verification=": "Verificación de propiedad: Google Search Console",
    "ms=": "Verificación de propiedad: Microsoft 365",
    "facebook-domain-verification=": "Verificación de propiedad: Facebook Business",
}
NS_PATTERNS = {
    "cloudflare.com": "Cloudflare (probable proxy/CDN delante del origen real)",
    "awsdns": "AWS Route 53",
    "domaincontrol.com": "GoDaddy",
}
MX_PATTERNS = {
    "google.com": "Google Workspace (correo corporativo)",
    "googlemail.com": "Google Workspace (correo corporativo)",
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "zoho.com": "Zoho Mail",
}
CNAME_PATTERNS = {
    "herokuapp.com": "Apunta a Heroku — revisar posible subdomain takeover si el recurso no existe",
    "github.io": "Apunta a GitHub Pages — revisar posible subdomain takeover si el recurso no existe",
    "s3.amazonaws.com": "Apunta a AWS S3 — revisar posible subdomain takeover si el bucket no existe",
    "s3-website": "Apunta a AWS S3 — revisar posible subdomain takeover si el bucket no existe",
    "cloudfront.net": "AWS CloudFront (CDN)",
    "azurewebsites.net": "Azure App Service — revisar posible subdomain takeover si el recurso no existe",
}
CAA_PATTERNS = {
    "letsencrypt.org": "Autoriza a Let's Encrypt a emitir certificados",
    "digicert.com": "Autoriza a DigiCert a emitir certificados",
    "sectigo.com": "Autoriza a Sectigo/Comodo a emitir certificados",
    "comodoca.com": "Autoriza a Sectigo/Comodo a emitir certificados",
}

BYPASS_403_PATH_SUFFIXES = ["/", "/.", "%20", "%09", "..;/"]
BYPASS_403_HEADERS = [
    "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-For",
    "X-Forwarded-Host", "X-Custom-IP-Authorization", "Referer",
]
