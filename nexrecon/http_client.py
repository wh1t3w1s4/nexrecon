"""Cliente HTTP centralizado.

En el bash, cada función hacía su propio `curl -s -k -L -A "$ua" ...`
suelto, repitiendo flags por todas partes. Aquí hay un único punto con
sesión persistente (reutiliza conexiones), rotación de User-Agent por
petición, timeouts consistentes y manejo de errores homogéneo.

Una sesión por hilo: `requests.Session` no está documentada como
thread-safe y este cliente se usa desde varios ThreadPoolExecutor a la vez.
"""
from __future__ import annotations

import ipaddress
import random
import threading
from dataclasses import dataclass

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import config
from .auth import AuthContext

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _cookie_domain(scope: str) -> str:
    """Dominio de cookie para `http.cookiejar` a partir del objetivo.

    Quita el puerto (las cookies no lo incluyen). Con nombres DNS usa punto
    inicial (host + subdominios); con IPs, coincidencia exacta; y los hosts
    sin punto (localhost) los trata cookiejar como `<host>.local`.
    """
    host = scope.rsplit("@", 1)[-1]
    host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host  # IPv6 sin corchetes: intacto
    host = host.strip("[]").lower()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if "." not in host:
        host += ".local"
    return f".{host}"


_RETRY = Retry(total=1, backoff_factor=0.5, status_forcelist=[])


@dataclass
class FetchResult:
    ok: bool
    status_code: int = 0
    headers: dict[str, str] | None = None
    set_cookie_raw: list[str] | None = None
    text: str = ""
    final_url: str = ""
    error: str = ""


class HttpClient:
    def __init__(self, timeout: int = config.HTTP_TIMEOUT,
                 auth: AuthContext | None = None, scope_domain: str | None = None):
        """`auth` + `scope_domain`: cookies de sesión (--cookie). Se acotan
        a `scope_domain` y sus subdominios; este mismo cliente consulta
        servicios de terceros (crt.sh, Shodan, ipinfo) y no deben recibirlas.
        """
        if auth and not scope_domain:
            raise ValueError("auth requiere scope_domain para no enviar la cookie a terceros")
        self.timeout = timeout
        self.auth = auth
        self._scope_domain = scope_domain
        self._local = threading.local()
        self._sessions: list[requests.Session] = []
        self._lock = threading.Lock()

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is not None:
            return session

        session = requests.Session()
        adapter = HTTPAdapter(max_retries=_RETRY)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.verify = False
        if self.auth:
            for name, value in self.auth.cookies.items():
                session.cookies.set(name, value, domain=_cookie_domain(self._scope_domain), path="/")
        self._local.session = session
        with self._lock:
            self._sessions.append(session)
        return session

    @staticmethod
    def random_ua() -> str:
        return random.choice(config.USER_AGENTS)

    def request(self, method: str, url: str, params: dict[str, str] | None = None,
                data: dict[str, str] | None = None, headers: dict[str, str] | None = None,
                allow_redirects: bool = True, timeout: int | None = None) -> FetchResult:
        """Punto de entrada genérico. `get()` es un atajo sobre este para no
        romper las llamadas existentes en el resto de módulos.
        """
        req_headers = {"User-Agent": self.random_ua()}
        if headers:
            req_headers.update(headers)
        try:
            resp = self._session().request(
                method, url, params=params, data=data, headers=req_headers,
                allow_redirects=allow_redirects, timeout=timeout or self.timeout,
            )
            try:
                set_cookie = resp.raw.headers.getlist("Set-Cookie")
            except Exception:
                sc = resp.headers.get("Set-Cookie")
                set_cookie = [sc] if sc else []
            return FetchResult(
                ok=True,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                set_cookie_raw=set_cookie,
                text=resp.text,
                final_url=resp.url,
            )
        except requests.RequestException as exc:
            return FetchResult(ok=False, error=str(exc))

    def get(self, url: str, headers: dict[str, str] | None = None,
            allow_redirects: bool = True, timeout: int | None = None) -> FetchResult:
        return self.request("GET", url, headers=headers,
                             allow_redirects=allow_redirects, timeout=timeout)

    def post(self, url: str, data: dict[str, str] | None = None,
             headers: dict[str, str] | None = None,
             allow_redirects: bool = True, timeout: int | None = None) -> FetchResult:
        return self.request("POST", url, data=data, headers=headers,
                             allow_redirects=allow_redirects, timeout=timeout)

    def status_only(self, url: str, headers: dict[str, str] | None = None,
                     allow_redirects: bool = True, timeout: int | None = None) -> int:
        result = self.get(url, headers=headers, allow_redirects=allow_redirects,
                           timeout=timeout)
        return result.status_code if result.ok else 0

    def close(self) -> None:
        with self._lock:
            for session in self._sessions:
                session.close()
            self._sessions.clear()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
