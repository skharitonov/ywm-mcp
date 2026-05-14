"""HTTP client + OAuth device flow for Yandex Webmaster API v4.1."""

import json
import os
import time
from pathlib import Path
from urllib.parse import quote

import httpx
from platformdirs import user_config_dir

BASE_URL = "https://api.webmaster.yandex.net/v4"
TIMEOUT = 30.0
MAX_RETRIES = 3
RETRY_STATUSES = {500, 502, 503}

DEVICE_CODE_URL = "https://oauth.yandex.ru/device/code"
TOKEN_URL = "https://oauth.yandex.ru/token"
SCOPES = "webmaster:hostinfo webmaster:verify"


def _token_dir() -> Path:
    """Return token storage directory, respecting YANDEX_WEBMASTER_TOKEN_DIR override."""
    override = os.environ.get("YANDEX_WEBMASTER_TOKEN_DIR")
    if override:
        return Path(override)
    return Path(user_config_dir("yandex-webmaster-mcp"))


def _token_path() -> Path:
    return _token_dir() / "token.json"


class WebmasterAPIError(Exception):
    """Yandex Webmaster API error."""

    def __init__(self, status_code: int, error_code: str, message: str):
        self.status_code = status_code
        self.error_code = error_code
        self.message = message
        super().__init__(f"[{status_code}] {error_code}: {message}")


class WebmasterClient:
    """Sync HTTP client for Yandex Webmaster API."""

    def __init__(self, token: str | None = None):
        # Auth priority:
        # 1. Explicit token arg (used by OAuthFlow after saving)
        # 2. YANDEX_WEBMASTER_API_KEY env var
        # 3. Token file (respects YANDEX_WEBMASTER_TOKEN_DIR)
        if token:
            self.token = token
        elif os.environ.get("YANDEX_WEBMASTER_API_KEY"):
            self.token = os.environ["YANDEX_WEBMASTER_API_KEY"]
        else:
            path = _token_path()
            if path.exists():
                try:
                    data = json.loads(path.read_text())
                    self.token = data.get("access_token")
                    if not self.token:
                        raise ValueError("token.json missing 'access_token' field")
                except (json.JSONDecodeError, OSError, ValueError) as e:
                    raise ValueError(f"Failed to read token file at {path}: {e}")
            else:
                raise ValueError(
                    "No authentication found. "
                    "Run start_auth(client_id) to authenticate, or set YANDEX_WEBMASTER_API_KEY."
                )

        self._client = httpx.Client(
            base_url=BASE_URL,
            headers={
                "Authorization": f"OAuth {self.token}",
                "Accept": "application/json",
                "Content-Type": "application/json; charset=UTF-8",
            },
            timeout=TIMEOUT,
        )

    @staticmethod
    def encode_host_id(host_id: str) -> str:
        """URL-encode host_id: 'https:example.com:443' -> 'https%3Aexample.com%3A443'."""
        return quote(host_id, safe="")

    def host_url(self, user_id: str, host_id: str) -> str:
        """Build base path for host endpoints."""
        return f"/user/{user_id}/hosts/{self.encode_host_id(host_id)}"

    def _request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        json_body: dict | None = None,
    ) -> dict | list | None:
        """Make HTTP request with retry on 500/502/503."""
        # Build query params, supporting list values (e.g. query_indicator)
        raw_params: list[tuple[str, str]] = []
        if params:
            for key, val in params.items():
                if val is None:
                    continue
                if isinstance(val, list):
                    for v in val:
                        raw_params.append((key, str(v)))
                else:
                    raw_params.append((key, str(val)))

        last_exc: Exception | None = None
        for attempt in range(MAX_RETRIES):
            try:
                resp = self._client.request(
                    method,
                    path,
                    params=raw_params if raw_params else None,
                    json=json_body,
                )

                if resp.status_code in RETRY_STATUSES and attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                    continue

                if resp.status_code == 204:
                    return None

                data = resp.json() if resp.content else {}

                if resp.status_code >= 400:
                    error_code = data.get("error_code", f"HTTP_{resp.status_code}")
                    error_msg = data.get("error_message", data.get("message", resp.text))
                    raise WebmasterAPIError(resp.status_code, error_code, error_msg)

                return data

            except httpx.TimeoutException as e:
                last_exc = e
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise WebmasterAPIError(0, "TIMEOUT", f"Request timed out: {e}")

            except httpx.HTTPError as e:
                last_exc = e
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise WebmasterAPIError(0, "CONNECTION_ERROR", str(e))

        raise WebmasterAPIError(0, "MAX_RETRIES", f"Failed after {MAX_RETRIES} retries: {last_exc}")

    def get(self, path: str, params: dict | None = None) -> dict | list | None:
        return self._request("GET", path, params=params)

    def post(self, path: str, params: dict | None = None, json_body: dict | None = None) -> dict | list | None:
        return self._request("POST", path, params=params, json_body=json_body)

    def delete(self, path: str) -> dict | list | None:
        return self._request("DELETE", path)


class OAuthFlow:
    """Yandex OAuth device code flow."""

    POLL_INTERVAL = 5      # seconds between token poll attempts
    POLL_TIMEOUT = 300     # 5 minutes total

    def request_device_code(self, client_id: str) -> dict:
        """POST to device/code endpoint, return {device_code, user_code, verification_url, expires_in, interval}."""
        resp = httpx.post(
            DEVICE_CODE_URL,
            data={"client_id": client_id, "scope": SCOPES},
            timeout=15,
        )
        if resp.status_code != 200:
            raise WebmasterAPIError(resp.status_code, "DEVICE_CODE_ERROR", resp.text)
        return resp.json()

    def poll_for_token(self, client_id: str, device_code: str) -> str:
        """Poll TOKEN_URL until approved or timed out. Returns access_token string."""
        deadline = time.time() + self.POLL_TIMEOUT
        while time.time() < deadline:
            resp = httpx.post(
                TOKEN_URL,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "code": device_code,
                    "client_id": client_id,
                },
                timeout=15,
            )
            try:
                data = resp.json()
            except Exception:
                raise WebmasterAPIError(resp.status_code, "JSON_DECODE_ERROR", resp.text)
            if resp.status_code == 200 and "access_token" in data:
                return data["access_token"]
            error = data.get("error", "")
            if error == "authorization_pending":
                time.sleep(self.POLL_INTERVAL)
                continue
            if error == "slow_down":
                time.sleep(self.POLL_INTERVAL * 2)
                continue
            raise WebmasterAPIError(resp.status_code, error, data.get("error_description", ""))
        raise WebmasterAPIError(0, "TIMEOUT", "Authorization timed out. Call start_auth again.")

    def save_token(self, access_token: str) -> Path:
        """Save token to platform config dir (or YANDEX_WEBMASTER_TOKEN_DIR override)."""
        dir_path = _token_dir()
        dir_path.mkdir(parents=True, exist_ok=True)
        token_file = dir_path / "token.json"
        token_file.write_text(json.dumps({"access_token": access_token, "token_type": "bearer"}))
        return token_file
