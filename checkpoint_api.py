"""Einfacher Client fuer die Check Point Management REST API (Python >= 3.9)."""

from typing import Any, Optional, Union

import requests


class CheckPointAPIError(RuntimeError):
    """Die Management API hat einen Fehler zurueckgegeben."""


class CheckPointAPI:
    """Login beim Erzeugen; API-Antworten werden als JSON-Dictionaries geliefert.

    ``server`` ist ein Hostname oder eine IP-Adresse, ohne URL-Pfad.
    ``verify`` kann alternativ den Pfad zu einem CA-Zertifikat enthalten.
    """

    def __init__(
        self,
        server: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        *,
        api_key: Optional[str] = None,
        domain: Optional[str] = None,
        port: int = 443,
        verify: Union[bool, str] = False,
        timeout: float = 30,
    ) -> None:
        if api_key is not None:
            if not api_key or username is not None or password is not None:
                raise ValueError("Entweder API-Key oder Benutzername und Passwort angeben.")
            credentials = {"api-key": api_key}
        else:
            if not username or not password:
                raise ValueError("Benutzername und Passwort oder API-Key erforderlich.")
            credentials = {"user": username, "password": password}
        if domain is not None:
            credentials["domain"] = domain
        if not server or any(char in server for char in "/?#@"):
            raise ValueError("server muss ein Hostname oder eine IP ohne URL-Pfad sein.")
        if not 1 <= int(port) <= 65535 or timeout <= 0:
            raise ValueError("Port oder Timeout ungueltig.")
        host = f"[{server}]" if ":" in server and not server.startswith("[") else server
        self.base_url = f"https://{host}:{int(port)}/web_api"
        self.timeout = timeout
        self.sid: Optional[str] = None
        self._session = requests.Session()
        self._session.verify = verify
        self._session.headers.update({"Content-Type": "application/json"})
        try:
            result = self._post("login", credentials)
            sid = result.get("sid")
            if not isinstance(sid, str) or not sid:
                raise CheckPointAPIError("Login-Antwort enthaelt keine gueltige Session-ID.")
            self.sid = sid
            self._session.headers["X-chkp-sid"] = sid
        except Exception:
            self._session.close()
            raise

    def _post(self, command: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self._session.post(
            f"{self.base_url}/{command}", json=payload, timeout=self.timeout
        )
        try:
            data = response.json()
        except ValueError as exc:
            raise CheckPointAPIError(
                f"{command}: keine JSON-Antwort (HTTP {response.status_code})."
            ) from exc
        if not response.ok:
            code = data.get("code", "") if isinstance(data, dict) else ""
            message = data.get("message", "API-Fehler") if isinstance(data, dict) else "API-Fehler"
            raise CheckPointAPIError(
                f"{command}: HTTP {response.status_code}, {code}: {message}"
            )
        if not isinstance(data, dict):
            raise CheckPointAPIError(f"{command}: JSON-Objekt erwartet.")
        return data

    def api_call(
        self, command: str, payload: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        """Fuehrt z. B. api_call('show-hosts', {'limit': 50}) aus.

        Netzwerkfehler loesen requests.RequestException aus; API-Fehler
        CheckPointAPIError. Aenderungen werden nicht automatisch publiziert.
        """
        if not command or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in command):
            raise ValueError("Ungueltiger API-Befehl.")
        if command in {"login", "logout"}:
            raise ValueError("Login erfolgt im Konstruktor; fuer Logout logout() verwenden.")
        if self.sid is None:
            raise CheckPointAPIError("Keine aktive Session.")
        return self._post(command, payload if payload is not None else {})

    def logout(self) -> None:
        """Beendet die Session und schliesst die HTTP-Verbindung."""
        try:
            if self.sid is not None:
                self._post("logout", {})
        finally:
            self.sid = None
            self._session.headers.pop("X-chkp-sid", None)
            self._session.close()

    def __enter__(self) -> "CheckPointAPI":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if exc_type is None:
            self.logout()
        else:
            try:
                self.logout()
            except Exception:
                pass  # Den urspruenglichen Fehler im with-Block beibehalten.
