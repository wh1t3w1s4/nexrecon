"""Cliente HTTP centralizado.

En el bash, cada función hacía su propio `curl -s -k -L -A "$ua" ...`
suelto, repitiendo flags por todas partes. Aquí hay un único punto con
sesión persistente (reutiliza conexiones), rotación de User-Agent por
petición, timeouts consistentes y manejo de errores homogéneo.

Una sesión por hilo: `requests.Session` no está documentada como
thread-safe y este cliente se usa desde varios ThreadPoolExecutor a la vez.
"""
from __future__ import annotations

import random
import threading
from dataclasses import dataclass

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
    def __init__(self, timeout: int = config.HTTP_TIMEOUT):
        self.timeout = timeout
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
        self._local.session = session
        with self._lock:
            self._sessions.append(session)
        return session

    @staticmethod
    def random_ua() -> str:
        return random.choice(config.USER_AGENTS)

    def get(self, url: str, headers: dict[str, str] | None = None,
            allow_redirects: bool = True, timeout: int | None = None) -> FetchResult:
        req_headers = {"User-Agent": self.random_ua()}
        if headers:
            req_headers.update(headers)
        try:
            resp = self._session().get(
                url, headers=req_headers, allow_redirects=allow_redirects,
                timeout=timeout or self.timeout,
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

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
