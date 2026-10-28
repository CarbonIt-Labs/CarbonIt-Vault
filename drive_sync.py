"""
drive_sync.py – Google Drive synchronisation for CarbonIt Vault.

Responsibilities
----------------
* OAuth 2.0 PKCE / loopback-server desktop flow (no client_secret required for
  installed-app / "Desktop" client but one IS required by Google's token endpoint
  for installed apps without Web-Application flow; we use the installed-app JSON
  and load it from the config file).
* Credential persistence via the OS keyring (secretstorage / libsecret on Linux,
  Windows Credential Manager on Windows).
* Google Drive folder + file management (drive.file scope, own files only).
* Version / ETag checking to prevent silent overwrites.
* Thread-safe upload/download with atomic local writes.
* Status callbacks so the UI always reflects the real state.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import logging
import os
import secrets
import shutil
import socket
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from typing import Callable, Optional

import keyring
import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEYRING_SERVICE = "CarbonIt-Vault"
KEYRING_CRED_KEY = "google_oauth_credentials"
KEYRING_USER_KEY = "google_user_info"
DRIVE_FOLDER_NAME = "CarbonIt Vault"
DRIVE_FILE_NAME = "vault.civ"
SYNC_META_FILENAME = ".carbonit_sync_meta.json"

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
DRIVE_API_BASE = "https://www.googleapis.com/drive/v3"
DRIVE_UPLOAD_BASE = "https://www.googleapis.com/upload/drive/v3"

SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/drive.file",
]


# ---------------------------------------------------------------------------
# Status constants (mirrored in app.js)
# ---------------------------------------------------------------------------

class SyncStatus:
    IDLE = "idle"
    SYNCED = "synced"
    PENDING = "sync_pending"
    SYNCING = "syncing"
    OFFLINE = "offline"
    AUTH_REQUIRED = "auth_required"
    CONFLICT = "conflict"
    FAILED = "sync_failed"
    DISCONNECTED = "disconnected"


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_oauth_config(config_path: Optional[Path] = None) -> Optional[dict]:
    """Load client_id / client_secret from a standard Google JSON file.

    Looks for the file in (in order):
      1. The *config_path* argument if given.
      2. ~/.carbonit/google_client_secrets.json
      3. The environment variable CARBONIT_OAUTH_CONFIG pointing to a file.
    Returns None when no config is found so the caller can show a helpful error.
    """
    candidates: list[Path] = []
    if config_path:
        candidates.append(Path(config_path))
    candidates.append(Path.home() / ".carbonit" / "google_client_secrets.json")
    env_path = os.environ.get("CARBONIT_OAUTH_CONFIG")
    if env_path:
        candidates.append(Path(env_path))

    for candidate in candidates:
        if candidate.exists():
            try:
                raw = json.loads(candidate.read_text(encoding="utf-8"))
                # Support both "installed" and "web" client JSON formats
                inner = raw.get("installed") or raw.get("web")
                if inner and inner.get("client_id"):
                    return inner
                # Flat format: {"client_id": ..., "client_secret": ...}
                if raw.get("client_id"):
                    return raw
            except Exception as exc:
                logger.warning("Could not read OAuth config %s: %s", candidate, exc)

    return None


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------

def _pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) using S256 method."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


# ---------------------------------------------------------------------------
# Loopback redirect server
# ---------------------------------------------------------------------------

class _OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """Capture the authorization code from Google's redirect."""

    def do_GET(self):
        self.server.result_path = self.path
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        # User-visible success page (ASCII-only bytes literal)
        html = (
            b"<!DOCTYPE html><html><head>"
            b"<meta charset=\"utf-8\">"
            b"<title>CarbonIt Vault - Connected</title>"
            b"<style>body{background:#07090b;color:#edfaff;font-family:sans-serif;"
            b"display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}"
            b".box{text-align:center;padding:40px;border:1px solid #263038;"
            b"border-radius:18px;background:rgba(16,20,24,.94);}"
            b".dot{display:inline-block;width:12px;height:12px;border-radius:50%;"
            b"background:#00e5ff;box-shadow:0 0 20px #00e5ff;margin-right:8px;}"
            b"h2{margin:12px 0 8px;color:#00e5ff;}p{color:#8d98a3;}</style></head>"
            b"<body><div class=\"box\"><div><span class=\"dot\"></span>CARBONIT VAULT</div>"
            b"<h2>Google Account Connected</h2>"
            b"<p>You may close this tab and return to CarbonIt Vault.</p>"
            b"</div></body></html>"
        )
        self.wfile.write(html)

    def log_message(self, *args):
        pass  # Suppress default access log


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Credential storage
# ---------------------------------------------------------------------------

def _save_credentials(creds: dict) -> None:
    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_CRED_KEY, json.dumps(creds))
    except Exception as exc:
        logger.warning("keyring save failed, falling back to local file: %s", exc)
        _fallback_path().write_text(json.dumps(creds), encoding="utf-8")
        _fallback_path().chmod(0o600)


def _load_credentials() -> Optional[dict]:
    try:
        raw = keyring.get_password(KEYRING_SERVICE, KEYRING_CRED_KEY)
        if raw:
            return json.loads(raw)
    except Exception as exc:
        logger.warning("keyring load failed: %s", exc)
    # Fallback to local file
    p = _fallback_path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return None


def _delete_credentials() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_CRED_KEY)
    except Exception:
        pass
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_USER_KEY)
    except Exception:
        pass
    fp = _fallback_path()
    if fp.exists():
        fp.unlink(missing_ok=True)
    up = _user_path()
    if up.exists():
        up.unlink(missing_ok=True)


def _fallback_path() -> Path:
    p = Path.home() / ".carbonit" / ".google_creds"
    p.parent.mkdir(exist_ok=True)
    return p


def _save_user_info(info: dict) -> None:
    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_USER_KEY, json.dumps(info))
    except Exception:
        _user_path().write_text(json.dumps(info), encoding="utf-8")
        _user_path().chmod(0o600)


def _load_user_info() -> Optional[dict]:
    try:
        raw = keyring.get_password(KEYRING_SERVICE, KEYRING_USER_KEY)
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    p = _user_path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return None


def _user_path() -> Path:
    p = Path.home() / ".carbonit" / ".google_user"
    p.parent.mkdir(exist_ok=True)
    return p


# ---------------------------------------------------------------------------
# Sync metadata (stores remote Drive file ID, remote version, local hash)
# ---------------------------------------------------------------------------

def _meta_path() -> Path:
    return Path.home() / ".carbonit" / SYNC_META_FILENAME


def _load_meta() -> dict:
    p = _meta_path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_meta(meta: dict) -> None:
    p = _meta_path()
    p.parent.mkdir(exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    os.replace(tmp, p)


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------

def _refresh_token(creds: dict, client_id: str, client_secret: str) -> Optional[dict]:
    """Exchange a refresh_token for a new access_token.  Returns updated creds or None."""
    if not creds.get("refresh_token"):
        return None
    try:
        resp = requests.post(GOOGLE_TOKEN_URL, data={
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": creds["refresh_token"],
            "grant_type": "refresh_token",
        }, timeout=15)
        resp.raise_for_status()
        token_data = resp.json()
        updated = dict(creds)
        updated["access_token"] = token_data["access_token"]
        updated["expires_at"] = time.time() + token_data.get("expires_in", 3600)
        if "refresh_token" in token_data:
            updated["refresh_token"] = token_data["refresh_token"]
        return updated
    except Exception as exc:
        logger.warning("Token refresh failed: %s", exc)
        return None


def _is_token_expired(creds: dict) -> bool:
    return time.time() >= creds.get("expires_at", 0) - 60


# ---------------------------------------------------------------------------
# Drive API helpers
# ---------------------------------------------------------------------------

def _drive_headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}


def _find_or_create_folder(access_token: str) -> str:
    """Return the Drive file-ID of the 'CarbonIt Vault' folder, creating it if needed."""
    # Search
    q = (
        f"name='{DRIVE_FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder'"
        " and trashed=false"
    )
    r = requests.get(
        f"{DRIVE_API_BASE}/files",
        params={"q": q, "spaces": "drive", "fields": "files(id,name)"},
        headers=_drive_headers(access_token),
        timeout=20,
    )
    r.raise_for_status()
    files = r.json().get("files", [])
    if files:
        return files[0]["id"]

    # Create
    r = requests.post(
        f"{DRIVE_API_BASE}/files",
        headers={**_drive_headers(access_token), "Content-Type": "application/json"},
        json={"name": DRIVE_FOLDER_NAME, "mimeType": "application/vnd.google-apps.folder"},
        timeout=20,
    )
    r.raise_for_status()
    return r.json()["id"]


def _find_vault_in_folder(access_token: str, folder_id: str) -> Optional[dict]:
    """Return the Drive file metadata for vault.civ, or None."""
    q = (
        f"name='{DRIVE_FILE_NAME}' and '{folder_id}' in parents"
        " and trashed=false"
    )
    r = requests.get(
        f"{DRIVE_API_BASE}/files",
        params={"q": q, "spaces": "drive", "fields": "files(id,name,md5Checksum,modifiedTime,size)"},
        headers=_drive_headers(access_token),
        timeout=20,
    )
    r.raise_for_status()
    files = r.json().get("files", [])
    return files[0] if files else None


def _upload_vault(access_token: str, folder_id: str, local_path: Path,
                  existing_file_id: Optional[str] = None) -> dict:
    """Upload (create or update) the vault file. Returns the file metadata."""
    content = local_path.read_bytes()
    meta: dict = {"name": DRIVE_FILE_NAME}
    if not existing_file_id:
        meta["parents"] = [folder_id]

    # Multipart upload
    boundary = "CarbonItVaultBoundary"
    body_parts = [
        f"--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{json.dumps(meta)}\r\n".encode(),
        f"--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n".encode(),
        content,
        f"\r\n--{boundary}--".encode(),
    ]
    body = b"".join(body_parts)

    headers = {
        **_drive_headers(access_token),
        "Content-Type": f"multipart/related; boundary={boundary}",
        "Content-Length": str(len(body)),
    }

    if existing_file_id:
        url = f"{DRIVE_UPLOAD_BASE}/files/{existing_file_id}?uploadType=multipart&fields=id,name,md5Checksum,modifiedTime"
        r = requests.patch(url, headers=headers, data=body, timeout=60)
    else:
        url = f"{DRIVE_UPLOAD_BASE}/files?uploadType=multipart&fields=id,name,md5Checksum,modifiedTime"
        r = requests.post(url, headers=headers, data=body, timeout=60)

    r.raise_for_status()
    return r.json()


def _download_vault(access_token: str, file_id: str, dest_path: Path) -> None:
    """Download the vault file atomically to dest_path."""
    r = requests.get(
        f"{DRIVE_API_BASE}/files/{file_id}?alt=media",
        headers=_drive_headers(access_token),
        stream=True,
        timeout=60,
    )
    r.raise_for_status()
    tmp = dest_path.with_suffix(".dl.tmp")
    try:
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(chunk_size=65536):
                f.write(chunk)
        os.replace(tmp, dest_path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def _get_remote_md5(access_token: str, file_id: str) -> Optional[str]:
    """Return the Drive-reported md5Checksum of a file, or None."""
    try:
        r = requests.get(
            f"{DRIVE_API_BASE}/files/{file_id}",
            params={"fields": "md5Checksum,modifiedTime"},
            headers=_drive_headers(access_token),
            timeout=15,
        )
        r.raise_for_status()
        return r.json().get("md5Checksum")
    except Exception:
        return None


def _local_md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Main DriveSync class
# ---------------------------------------------------------------------------

class DriveSync:
    """
    Thread-safe Google Drive sync manager.

    Usage:
        ds = DriveSync()
        ds.on_status_change = lambda s, msg: ...   # hook for UI updates
        ds.start_auth()          # opens browser
        ds.upload(vault_path)
        ds.download(vault_path)
    """

    def __init__(self, vault_path: Optional[Path] = None) -> None:
        self._lock = threading.Lock()
        self._creds: Optional[dict] = None
        self._user_info: Optional[dict] = None
        self._oauth_config: Optional[dict] = None
        self._status: str = SyncStatus.DISCONNECTED
        self._last_synced: Optional[str] = None
        self._conflict_remote_path: Optional[Path] = None
        self.vault_path = vault_path or (Path.home() / ".carbonit" / "carbonit_vault.civ")

        # Callbacks — set by app.py
        self.on_status_change: Optional[Callable[[str, str], None]] = None

        # Load persisted state
        self._creds = _load_credentials()
        self._user_info = _load_user_info()
        self._oauth_config = load_oauth_config()

        if self._creds and self._user_info:
            self._set_status(SyncStatus.IDLE, "")
        else:
            self._set_status(SyncStatus.DISCONNECTED, "")

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def _set_status(self, status: str, message: str = "") -> None:
        self._status = status
        if self.on_status_change:
            try:
                self.on_status_change(status, message)
            except Exception:
                pass

    def get_state(self) -> dict:
        """Return a JSON-serialisable state dict for the frontend."""
        meta = _load_meta()
        return {
            "connected": bool(self._creds and self._user_info),
            "email": (self._user_info or {}).get("email"),
            "name": (self._user_info or {}).get("name"),
            "picture": (self._user_info or {}).get("picture"),
            "status": self._status,
            "last_synced": self._last_synced or meta.get("last_synced"),
            "conflict": self._conflict_remote_path is not None,
            "conflict_remote_path": str(self._conflict_remote_path) if self._conflict_remote_path else None,
            "oauth_configured": self._oauth_config is not None,
        }

    # ------------------------------------------------------------------
    # OAuth – public methods called by Flask routes
    # ------------------------------------------------------------------

    def configure_oauth(self, config_path: Optional[str] = None) -> bool:
        """Reload OAuth config from disk. Returns True if config found."""
        self._oauth_config = load_oauth_config(Path(config_path) if config_path else None)
        return self._oauth_config is not None

    def start_auth(self) -> dict:
        """
        Launch the PKCE OAuth flow in the system browser.
        Blocks until the user completes auth or times out (~3 min).
        Returns {"ok": True} on success or {"error": str} on failure.
        """
        if not self._oauth_config:
            return {"error": "No OAuth client configuration found. See setup instructions."}

        client_id = self._oauth_config.get("client_id", "")
        client_secret = self._oauth_config.get("client_secret", "")
        if not client_id:
            return {"error": "client_id missing from OAuth config."}

        verifier, challenge = _pkce_pair()
        state = secrets.token_urlsafe(16)
        port = _find_free_port()
        redirect_uri = f"http://127.0.0.1:{port}"

        auth_url = (
            "https://accounts.google.com/o/oauth2/v2/auth?"
            + urllib.parse.urlencode({
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": " ".join(SCOPES),
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "access_type": "offline",
                "prompt": "consent",
            })
        )

        # Start loopback server
        server = http.server.HTTPServer(("127.0.0.1", port), _OAuthCallbackHandler)
        server.result_path = None  # type: ignore[attr-defined]
        server.timeout = 180  # 3 minutes

        try:
            webbrowser.open(auth_url)
        except Exception as exc:
            return {"error": f"Could not open browser: {exc}"}

        # Wait for callback (with timeout)
        deadline = time.time() + 180
        while server.result_path is None and time.time() < deadline:
            server.handle_request()

        if server.result_path is None:
            return {"error": "Authentication timed out. Please try again."}

        parsed = urllib.parse.urlparse(server.result_path)
        params = urllib.parse.parse_qs(parsed.query)

        if "error" in params:
            return {"error": f"Google returned error: {params['error'][0]}"}

        returned_state = params.get("state", [None])[0]
        if returned_state != state:
            return {"error": "State mismatch – possible CSRF. Authentication rejected."}

        code = params.get("code", [None])[0]
        if not code:
            return {"error": "No authorization code received."}

        # Exchange code for tokens
        try:
            token_resp = requests.post(GOOGLE_TOKEN_URL, data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "code_verifier": verifier,
            }, timeout=20)
            token_resp.raise_for_status()
            token_data = token_resp.json()
        except Exception as exc:
            return {"error": f"Token exchange failed: {exc}"}

        creds = {
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token"),
            "expires_at": time.time() + token_data.get("expires_in", 3600),
            "token_type": token_data.get("token_type", "Bearer"),
        }

        # Fetch user info
        try:
            ui_resp = requests.get(
                GOOGLE_USERINFO_URL,
                headers=_drive_headers(creds["access_token"]),
                timeout=10,
            )
            ui_resp.raise_for_status()
            user_info = ui_resp.json()
        except Exception as exc:
            return {"error": f"Could not fetch user info: {exc}"}

        _save_credentials(creds)
        _save_user_info(user_info)

        with self._lock:
            self._creds = creds
            self._user_info = user_info

        self._set_status(SyncStatus.IDLE, "")
        return {"ok": True, "email": user_info.get("email")}

    def disconnect(self) -> dict:
        """Revoke the token and remove stored credentials. Local vault is untouched."""
        with self._lock:
            creds = self._creds

        if creds and creds.get("access_token"):
            try:
                requests.post(
                    GOOGLE_REVOKE_URL,
                    params={"token": creds["access_token"]},
                    timeout=10,
                )
            except Exception:
                pass  # Best-effort revocation

        _delete_credentials()
        with self._lock:
            self._creds = None
            self._user_info = None

        self._set_status(SyncStatus.DISCONNECTED, "")
        return {"ok": True}

    # ------------------------------------------------------------------
    # Vault upload / download (public, called from Flask routes)
    # ------------------------------------------------------------------

    def _ensure_valid_token(self) -> Optional[str]:
        """Return a valid access token, refreshing if necessary. None on failure."""
        with self._lock:
            creds = dict(self._creds) if self._creds else None

        if not creds:
            return None

        if _is_token_expired(creds):
            cfg = self._oauth_config or {}
            updated = _refresh_token(creds, cfg.get("client_id", ""), cfg.get("client_secret", ""))
            if updated is None:
                self._set_status(SyncStatus.AUTH_REQUIRED, "Token refresh failed.")
                return None
            _save_credentials(updated)
            with self._lock:
                self._creds = updated
            return updated["access_token"]

        return creds["access_token"]

    def upload(self, vault_path: Optional[Path] = None) -> dict:
        """Upload the vault to Drive. Returns {"ok": True} or {"error": str}."""
        path = vault_path or self.vault_path
        if not path.exists():
            return {"error": "No local vault to upload."}

        token = self._ensure_valid_token()
        if not token:
            return {"error": "Not authenticated. Please connect Google."}

        self._set_status(SyncStatus.SYNCING, "Uploading vault…")
        try:
            folder_id = _find_or_create_folder(token)
            meta = _load_meta()
            existing_id = meta.get("drive_file_id")

            # Check remote hasn't changed since our last known upload
            if existing_id:
                remote_md5 = _get_remote_md5(token, existing_id)
                known_remote_md5 = meta.get("last_remote_md5")
                if remote_md5 and known_remote_md5 and remote_md5 != known_remote_md5:
                    # Remote changed – conflict
                    self._set_status(SyncStatus.CONFLICT,
                                     "Remote vault changed. Download conflict copy first.")
                    return {"error": "conflict", "message":
                            "The remote vault has been modified by another device. "
                            "Download the remote version before uploading to avoid data loss."}

            file_meta = _upload_vault(token, folder_id, path, existing_id)
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            meta.update({
                "drive_file_id": file_meta["id"],
                "drive_folder_id": folder_id,
                "last_remote_md5": file_meta.get("md5Checksum", _local_md5(path)),
                "last_synced": now,
                "last_local_md5": _local_md5(path),
            })
            _save_meta(meta)
            self._last_synced = now
            self._set_status(SyncStatus.SYNCED, "")
            return {"ok": True, "synced_at": now}

        except requests.exceptions.ConnectionError:
            self._set_status(SyncStatus.OFFLINE, "No network connection.")
            return {"error": "offline"}
        except Exception as exc:
            logger.exception("Upload failed")
            self._set_status(SyncStatus.FAILED, str(exc))
            return {"error": str(exc)}

    def download(self, dest_path: Optional[Path] = None, force: bool = False) -> dict:
        """
        Download the remote vault.

        If *dest_path* already exists AND differs from the remote, this method
        will save the remote copy to a .conflict file and return
        {"conflict": True, "conflict_path": ...} so the caller can decide.

        Pass force=True to overwrite without conflict checking (e.g. first-time restore).
        """
        path = dest_path or self.vault_path
        token = self._ensure_valid_token()
        if not token:
            return {"error": "Not authenticated. Please connect Google."}

        self._set_status(SyncStatus.SYNCING, "Downloading vault…")
        try:
            folder_id = _find_or_create_folder(token)
            remote_file = _find_vault_in_folder(token, folder_id)
            if not remote_file:
                self._set_status(SyncStatus.IDLE, "")
                return {"error": "no_remote", "message": "No vault found in Google Drive."}

            remote_md5 = remote_file.get("md5Checksum")
            file_id = remote_file["id"]

            # Conflict detection
            if path.exists() and not force:
                local_md5 = _local_md5(path)
                meta = _load_meta()
                known_remote_md5 = meta.get("last_remote_md5")

                if remote_md5 and remote_md5 == local_md5:
                    # Already identical
                    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    self._last_synced = now
                    self._set_status(SyncStatus.SYNCED, "")
                    return {"ok": True, "already_synced": True}

                if remote_md5 and known_remote_md5 and remote_md5 != known_remote_md5:
                    # Both local and remote changed
                    conflict_path = path.parent / f"vault_conflict_{int(time.time())}.civ"
                    _download_vault(token, file_id, conflict_path)
                    self._conflict_remote_path = conflict_path
                    self._set_status(SyncStatus.CONFLICT,
                                     f"Conflict: remote saved to {conflict_path.name}")
                    return {
                        "conflict": True,
                        "conflict_path": str(conflict_path),
                        "message": (
                            "Both local and remote vaults have changed. "
                            f"Remote copy saved to {conflict_path.name}. "
                            "Unlock your local vault or restore from the conflict copy."
                        ),
                    }

                if not known_remote_md5:
                    # First time seeing remote; local exists → conflict
                    conflict_path = path.parent / f"vault_conflict_{int(time.time())}.civ"
                    _download_vault(token, file_id, conflict_path)
                    self._conflict_remote_path = conflict_path
                    self._set_status(SyncStatus.CONFLICT,
                                     f"Remote vault found: saved to {conflict_path.name}")
                    return {
                        "conflict": True,
                        "conflict_path": str(conflict_path),
                        "message": (
                            "A remote vault exists and a local vault is also present. "
                            f"Remote copy saved to {conflict_path.name}. "
                            "Resolve the conflict before proceeding."
                        ),
                    }

            # Safe to download (first-time or forced)
            # Back up existing local vault if present
            if path.exists():
                backup = path.parent / f"vault_backup_{int(time.time())}.civ"
                shutil.copy2(path, backup)
                logger.info("Backed up local vault to %s", backup)

            _download_vault(token, file_id, path)
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            meta = _load_meta()
            meta.update({
                "drive_file_id": file_id,
                "drive_folder_id": folder_id,
                "last_remote_md5": remote_md5 or _local_md5(path),
                "last_synced": now,
                "last_local_md5": _local_md5(path),
            })
            _save_meta(meta)
            self._last_synced = now
            self._conflict_remote_path = None
            self._set_status(SyncStatus.SYNCED, "")
            return {"ok": True, "synced_at": now}

        except requests.exceptions.ConnectionError:
            self._set_status(SyncStatus.OFFLINE, "No network connection.")
            return {"error": "offline"}
        except Exception as exc:
            logger.exception("Download failed")
            self._set_status(SyncStatus.FAILED, str(exc))
            return {"error": str(exc)}

    def check_remote(self) -> dict:
        """
        Check if a remote vault exists without downloading.
        Returns {"exists": bool, "file_id": ..., "modified": ...} or {"error": ...}.
        """
        token = self._ensure_valid_token()
        if not token:
            return {"error": "Not authenticated."}

        try:
            folder_id = _find_or_create_folder(token)
            remote_file = _find_vault_in_folder(token, folder_id)
            if remote_file:
                return {
                    "exists": True,
                    "file_id": remote_file["id"],
                    "modified": remote_file.get("modifiedTime"),
                    "size": remote_file.get("size"),
                }
            return {"exists": False}
        except requests.exceptions.ConnectionError:
            return {"error": "offline"}
        except Exception as exc:
            return {"error": str(exc)}

    def resolve_conflict_use_local(self) -> dict:
        """Discard the conflict copy and upload the local vault as authoritative."""
        if self._conflict_remote_path and self._conflict_remote_path.exists():
            self._conflict_remote_path.unlink(missing_ok=True)
        self._conflict_remote_path = None
        # Force-upload local
        meta = _load_meta()
        meta.pop("last_remote_md5", None)
        _save_meta(meta)
        return self.upload()

    def resolve_conflict_use_remote(self) -> dict:
        """Replace local vault with the already-downloaded conflict copy."""
        if not self._conflict_remote_path or not self._conflict_remote_path.exists():
            return {"error": "No conflict copy available."}

        vault_path = self.vault_path
        backup = vault_path.parent / f"vault_backup_{int(time.time())}.civ"
        if vault_path.exists():
            shutil.copy2(vault_path, backup)

        os.replace(self._conflict_remote_path, vault_path)
        self._conflict_remote_path = None

        # Update local md5
        meta = _load_meta()
        meta["last_local_md5"] = _local_md5(vault_path)
        meta["last_remote_md5"] = _local_md5(vault_path)
        _save_meta(meta)

        self._set_status(SyncStatus.SYNCED, "")
        return {"ok": True, "backup_path": str(backup)}

    # ------------------------------------------------------------------
    # Auto-sync hook (called after every local vault save)
    # ------------------------------------------------------------------

    def upload_after_save(self, vault_path: Optional[Path] = None) -> None:
        """Non-blocking upload triggered after every vault save."""
        if not (self._creds and self._user_info):
            return
        t = threading.Thread(target=self._bg_upload, args=(vault_path,), daemon=True)
        t.start()

    def _bg_upload(self, vault_path: Optional[Path]) -> None:
        try:
            self.upload(vault_path)
        except Exception:
            logger.exception("Background upload failed")
