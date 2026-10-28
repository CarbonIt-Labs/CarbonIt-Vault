"""
tests/test_drive_sync.py – CarbonIt Vault Google Drive sync test suite.

All tests use mocked HTTP calls and temporary directories.
No real Google account, real vault files, or real network calls are used.

Run with:
    .venv/bin/python -m pytest tests/test_drive_sync.py -v
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

# ── Make sure we can import from the project root ──────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drive_sync import (
    DriveSync,
    SyncStatus,
    _local_md5,
    _load_meta,
    _save_meta,
    _pkce_pair,
    load_oauth_config,
    _fallback_path,
    _user_path,
)
import drive_sync as ds_module


# ── Helpers ────────────────────────────────────────────────────────────────

def _make_civ(path: Path, content: str = "FAKE_VAULT_DATA") -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def _md5(content: str) -> str:
    return hashlib.md5(content.encode()).hexdigest()


def _make_drive_sync(tmp_dir: Path) -> DriveSync:
    """Create a DriveSync pointing at a temp directory, bypassing keyring."""
    vault = tmp_dir / "carbonit_vault.civ"
    with (
        patch("drive_sync._load_credentials", return_value=None),
        patch("drive_sync._load_user_info",   return_value=None),
        patch("drive_sync.load_oauth_config",  return_value={"client_id": "TEST_ID", "client_secret": "TEST_SECRET"}),
        patch("drive_sync._meta_path",         return_value=tmp_dir / ".meta.json"),
        patch("drive_sync._fallback_path",     return_value=tmp_dir / ".creds"),
        patch("drive_sync._user_path",         return_value=tmp_dir / ".user"),
    ):
        drive = DriveSync(vault_path=vault)
    return drive


# ══════════════════════════════════════════════════════════════════════════════
# 1. Existing vault creation and unlocking still work
# ══════════════════════════════════════════════════════════════════════════════
class TestExistingVaultCompat(unittest.TestCase):
    """Verify crypto.py round-trip is unaffected by drive_sync import."""

    def test_create_and_unlock(self):
        from crypto import create_vault, unlock_vault, save_unlocked_vault
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "vault.civ"
            vault_data, vault_key = create_vault("CorrectHorseBatteryStaple!!")
            p.write_text(json.dumps(vault_data, indent=2), encoding="utf-8")

            result, key2 = unlock_vault(p, "CorrectHorseBatteryStaple!!")
            self.assertIsInstance(result["entries"], list)
            self.assertEqual(len(result["entries"]), 0)

    def test_wrong_password_raises(self):
        from crypto import create_vault, unlock_vault
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "vault.civ"
            vault_data, _ = create_vault("CorrectHorseBatteryStaple!!")
            p.write_text(json.dumps(vault_data, indent=2), encoding="utf-8")
            with self.assertRaises(Exception):
                unlock_vault(p, "WrongPassword!!")

    def test_save_and_reload_entries(self):
        from crypto import create_vault, unlock_vault, save_unlocked_vault
        import secrets as sec
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "vault.civ"
            vault_data, vault_key = create_vault("CorrectHorseBatteryStaple!!")
            p.write_text(json.dumps(vault_data, indent=2), encoding="utf-8")
            result, key = unlock_vault(p, "CorrectHorseBatteryStaple!!")
            entries = [{"id": sec.token_hex(8), "name": "Test Site", "username": "user",
                        "password": "p@ss", "url": "https://test.com"}]
            save_unlocked_vault(p, result["raw"], entries, key)
            result2, _ = unlock_vault(p, "CorrectHorseBatteryStaple!!")
            self.assertEqual(result2["entries"][0]["name"], "Test Site")


# ══════════════════════════════════════════════════════════════════════════════
# 2. Local vaults can be opened without Google connected
# ══════════════════════════════════════════════════════════════════════════════
class TestLocalNoGoogle(unittest.TestCase):
    def test_flask_unlock_without_google(self):
        """Flask /api/unlock must work with no Drive credentials stored."""
        from crypto import create_vault
        with tempfile.TemporaryDirectory() as tmp:
            vault_path = Path(tmp) / "carbonit_vault.civ"
            vault_data, _ = create_vault("CorrectHorseBatteryStaple!!")
            vault_path.write_text(json.dumps(vault_data, indent=2), encoding="utf-8")

            with (
                patch("drive_sync._load_credentials", return_value=None),
                patch("drive_sync._load_user_info",   return_value=None),
                patch("drive_sync.load_oauth_config",  return_value=None),
                patch("app.VAULT_PATH", vault_path),
                patch("app.data_dir", Path(tmp)),
            ):
                import app as app_module
                app_module.VAULT_PATH = vault_path
                app_module.UNLOCKED.clear()
                client = app_module.app.test_client()
                resp = client.post("/api/unlock",
                                   json={"master_password": "CorrectHorseBatteryStaple!!"})
                self.assertEqual(resp.status_code, 200)
                data = resp.get_json()
                self.assertTrue(data["ok"])
                self.assertIn("token", data)


# ══════════════════════════════════════════════════════════════════════════════
# 3. OAuth flow can be initiated and cancelled
# ══════════════════════════════════════════════════════════════════════════════
class TestOAuthFlow(unittest.TestCase):
    def test_no_config_returns_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive_sync(Path(tmp))
            drive._oauth_config = None  # simulate missing config
            result = drive.start_auth()
            self.assertIn("error", result)

    def test_pkce_pair_unique(self):
        v1, c1 = _pkce_pair()
        v2, c2 = _pkce_pair()
        self.assertNotEqual(v1, v2)
        self.assertNotEqual(c1, c2)
        # challenge must be URL-safe base64
        import base64
        base64.urlsafe_b64decode(c1 + "==")  # should not raise

    def test_auth_browser_open_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive_sync(Path(tmp))
            drive._oauth_config = {"client_id": "ID", "client_secret": "SEC"}
            with (
                patch("webbrowser.open", side_effect=Exception("no browser")),
                patch("drive_sync._find_free_port", return_value=19876),
                patch("http.server.HTTPServer", MagicMock()),
            ):
                result = drive.start_auth()
                self.assertIn("error", result)


# ══════════════════════════════════════════════════════════════════════════════
# 4. Upload a newly created vault
# ══════════════════════════════════════════════════════════════════════════════
class TestUpload(unittest.TestCase):

    def _make_authenticated_drive(self, tmp):
        drive = _make_drive_sync(tmp)
        drive._creds = {"access_token": "TOKEN", "expires_at": time.time() + 3600}
        drive._user_info = {"email": "user@example.com"}
        return drive

    def test_upload_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            drive = self._make_authenticated_drive(tmp_path)
            vault = _make_civ(tmp_path / "carbonit_vault.civ", "ENCRYPTED_BLOB")
            drive.vault_path = vault

            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {
                "files": [{"id": "FOLDER_ID", "name": "CarbonIt Vault"}]
            }

            upload_resp = MagicMock()
            upload_resp.raise_for_status = MagicMock()
            upload_resp.json.return_value = {
                "id": "FILE_ID", "name": "vault.civ", "md5Checksum": _md5("ENCRYPTED_BLOB")
            }

            with (
                patch("requests.get",  return_value=mock_resp),
                patch("requests.post", return_value=upload_resp),
                patch("requests.patch",return_value=upload_resp),
                patch("drive_sync._meta_path", return_value=tmp_path / ".meta.json"),
            ):
                result = drive.upload(vault)

            self.assertTrue(result.get("ok"), result)
            self.assertIn("synced_at", result)

    def test_upload_without_credentials_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive_sync(Path(tmp))
            drive._creds = None
            vault = _make_civ(Path(tmp) / "vault.civ")
            result = drive.upload(vault)
            self.assertIn("error", result)

    def test_upload_when_no_vault_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            drive = self._make_authenticated_drive(Path(tmp))
            result = drive.upload(Path(tmp) / "nonexistent.civ")
            self.assertIn("error", result)


# ══════════════════════════════════════════════════════════════════════════════
# 5. Download vault on a second-device setup (no local vault present)
# ══════════════════════════════════════════════════════════════════════════════
class TestDownloadFirstTime(unittest.TestCase):

    def test_download_creates_local_vault(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            drive = _make_drive_sync(tmp_path)
            drive._creds = {"access_token": "TOKEN", "expires_at": time.time() + 3600}
            drive._user_info = {"email": "user@example.com"}
            vault_path = tmp_path / "carbonit_vault.civ"
            drive.vault_path = vault_path
            self.assertFalse(vault_path.exists())

            FOLDER_CONTENT = b"ENCRYPTED_VAULT_BYTES"
            REMOTE_MD5 = hashlib.md5(FOLDER_CONTENT).hexdigest()

            folder_resp = MagicMock()
            folder_resp.raise_for_status = MagicMock()
            folder_resp.json.side_effect = [
                {"files": [{"id": "FOLDER_ID"}]},           # find folder
                {"files": [{"id": "FILE_ID", "name": "vault.civ",
                            "md5Checksum": REMOTE_MD5, "modifiedTime": "2026-01-01T00:00:00Z",
                            "size": "100"}]},                # find file
            ]

            download_resp = MagicMock()
            download_resp.raise_for_status = MagicMock()
            download_resp.iter_content = MagicMock(return_value=[FOLDER_CONTENT])

            with (
                patch("requests.get",  side_effect=[folder_resp, folder_resp, download_resp]),
                patch("drive_sync._meta_path", return_value=tmp_path / ".meta.json"),
            ):
                result = drive.download(vault_path, force=True)

            self.assertTrue(result.get("ok"), result)
            self.assertTrue(vault_path.exists())
            self.assertEqual(vault_path.read_bytes(), FOLDER_CONTENT)


# ══════════════════════════════════════════════════════════════════════════════
# 6. Same account on two devices finds same cloud vault
# ══════════════════════════════════════════════════════════════════════════════
class TestMultiDeviceDiscovery(unittest.TestCase):
    def test_check_remote_finds_vault(self):
        with tempfile.TemporaryDirectory() as tmp:
            drive = _make_drive_sync(Path(tmp))
            drive._creds = {"access_token": "TOKEN", "expires_at": time.time() + 3600}
            drive._user_info = {"email": "user@example.com"}

            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.json.side_effect = [
                {"files": [{"id": "FOLDER_ID"}]},
                {"files": [{"id": "FILE_ID", "name": "vault.civ",
                            "modifiedTime": "2026-01-01T00:00:00Z", "size": "200"}]},
            ]
            with patch("requests.get", return_value=resp):
                result = drive.check_remote()

            self.assertTrue(result.get("exists"))
            self.assertEqual(result["file_id"], "FILE_ID")


# ══════════════════════════════════════════════════════════════════════════════
# 7. Updating vault updates remote file, no duplicates
# ══════════════════════════════════════════════════════════════════════════════
class TestUpdateNoDuplicates(unittest.TestCase):
    def test_upload_uses_existing_file_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            drive = _make_drive_sync(tmp_path)
            drive._creds = {"access_token": "TOKEN", "expires_at": time.time() + 3600}
            drive._user_info = {"email": "user@example.com"}
            vault = _make_civ(tmp_path / "vault.civ", "DATA_V2")
            drive.vault_path = vault

            content = b"DATA_V2"
            known_md5 = hashlib.md5(content).hexdigest()

            # Pre-existing sync meta with known remote md5
            meta_path = tmp_path / ".meta.json"
            _save_meta_path = lambda: meta_path
            meta = {
                "drive_file_id": "EXISTING_FILE_ID",
                "drive_folder_id": "FOLDER_ID",
                "last_remote_md5": known_md5,  # matches so no conflict
            }
            meta_path.write_text(json.dumps(meta), encoding="utf-8")

            folder_resp = MagicMock()
            folder_resp.raise_for_status = MagicMock()
            folder_resp.json.side_effect = [
                {"files": [{"id": "FOLDER_ID"}]},     # find folder
                {"md5Checksum": known_md5},            # remote md5 check
            ]
            patch_resp = MagicMock()
            patch_resp.raise_for_status = MagicMock()
            patch_resp.json.return_value = {
                "id": "EXISTING_FILE_ID", "name": "vault.civ", "md5Checksum": known_md5
            }

            patch_calls = []
            def mock_patch(*a, **kw):
                patch_calls.append((a, kw))
                return patch_resp

            with (
                patch("requests.get",   return_value=folder_resp),
                patch("requests.patch", side_effect=mock_patch),
                patch("requests.post",  MagicMock()),
                patch("drive_sync._meta_path", return_value=meta_path),
            ):
                result = drive.upload(vault)

            # PATCH (update) must have been called, not POST (create new)
            self.assertTrue(len(patch_calls) > 0, "Expected PATCH call for existing file")
            self.assertTrue(result.get("ok"), result)


# ══════════════════════════════════════════════════════════════════════════════
# 8. Newer remote changes block upload (no silent overwrite)
# ══════════════════════════════════════════════════════════════════════════════
class TestConflictDetectionOnUpload(unittest.TestCase):
    def test_upload_blocked_when_remote_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            drive = _make_drive_sync(tmp_path)
            drive._creds = {"access_token": "TOKEN", "expires_at": time.time() + 3600}
            drive._user_info = {"email": "user@example.com"}
            vault = _make_civ(tmp_path / "vault.civ", "LOCAL_DATA")
            drive.vault_path = vault

            meta_path = tmp_path / ".meta.json"
            meta = {
                "drive_file_id": "FILE_ID",
                "last_remote_md5": "OLD_MD5",   # what we last uploaded
            }
            meta_path.write_text(json.dumps(meta))

            folder_resp = MagicMock()
            folder_resp.raise_for_status = MagicMock()
            folder_resp.json.side_effect = [
                {"files": [{"id": "FOLDER_ID"}]},
                {"md5Checksum": "NEW_REMOTE_MD5_DIFFERENT"},  # remote changed
            ]

            with (
                patch("requests.get", return_value=folder_resp),
                patch("drive_sync._meta_path", return_value=meta_path),
            ):
                result = drive.upload(vault)

            self.assertEqual(result.get("error"), "conflict")
            self.assertIn("message", result)


# ══════════════════════════════════════════════════════════════════════════════
# 9. Conflict preserves recoverable copies
# ══════════════════════════════════════════════════════════════════════════════
class TestConflictResolution(unittest.TestCase):
    def test_conflict_saves_remote_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            drive = _make_drive_sync(tmp_path)
            drive._creds = {"access_token": "TOKEN", "expires_at": time.time() + 3600}
            drive._user_info = {"email": "user@example.com"}

            # Local vault already exists
            vault = _make_civ(tmp_path / "vault.civ", "LOCAL_DATA")
            drive.vault_path = vault

            old_remote_md5 = _md5("OLD_REMOTE")
            new_remote_md5 = _md5("NEW_REMOTE")

            meta_path = tmp_path / ".meta.json"
            meta = {"drive_file_id": "FILE_ID", "last_remote_md5": old_remote_md5}
            meta_path.write_text(json.dumps(meta))

            folder_resp = MagicMock()
            folder_resp.raise_for_status = MagicMock()
            folder_resp.json.side_effect = [
                {"files": [{"id": "FOLDER_ID"}]},
                {"files": [{"id": "FILE_ID", "name": "vault.civ",
                            "md5Checksum": new_remote_md5,
                            "modifiedTime": "2026-01-01"}]},
            ]

            download_resp = MagicMock()
            download_resp.raise_for_status = MagicMock()
            download_resp.iter_content = MagicMock(return_value=[b"NEW_REMOTE"])

            with (
                patch("requests.get", side_effect=[folder_resp, folder_resp, download_resp]),
                patch("drive_sync._meta_path", return_value=meta_path),
            ):
                result = drive.download(vault, force=False)

            self.assertTrue(result.get("conflict"), result)
            conflict_path = Path(result["conflict_path"])
            self.assertTrue(conflict_path.exists(), "Conflict copy should be saved to disk")
            # Original local vault must be intact
            self.assertTrue(vault.exists())
            self.assertEqual(vault.read_text(), "LOCAL_DATA")

    def test_resolve_use_local_uploads(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            drive = _make_drive_sync(tmp_path)
            drive._creds = {"access_token": "TOKEN", "expires_at": time.time() + 3600}
            drive._user_info = {"email": "user@example.com"}
            vault = _make_civ(tmp_path / "vault.civ", "LOCAL")
            drive.vault_path = vault

            # Pre-set a fake conflict copy
            conflict = tmp_path / "vault_conflict_123.civ"
            conflict.write_text("REMOTE_CONFLICT")
            drive._conflict_remote_path = conflict

            meta_path = tmp_path / ".meta.json"
            meta_path.write_text("{}")

            folder_resp = MagicMock()
            folder_resp.raise_for_status = MagicMock()
            folder_resp.json.side_effect = [
                {"files": [{"id": "FOLDER_ID"}]},
            ]
            post_resp = MagicMock()
            post_resp.raise_for_status = MagicMock()
            post_resp.json.return_value = {"id": "FILE_ID", "md5Checksum": _md5("LOCAL")}

            with (
                patch("requests.get",   return_value=folder_resp),
                patch("requests.post",  return_value=post_resp),
                patch("requests.patch", return_value=post_resp),
                patch("drive_sync._meta_path", return_value=meta_path),
            ):
                result = drive.resolve_conflict_use_local()

            self.assertTrue(result.get("ok"), result)
            self.assertFalse(conflict.exists(), "Conflict copy should be deleted")

    def test_resolve_use_remote_replaces_local(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            drive = _make_drive_sync(tmp_path)
            vault = _make_civ(tmp_path / "vault.civ", "LOCAL_OLD")
            drive.vault_path = vault

            conflict = tmp_path / "vault_conflict_456.civ"
            conflict.write_text("REMOTE_GOOD")
            drive._conflict_remote_path = conflict

            meta_path = tmp_path / ".meta.json"
            meta_path.write_text("{}")

            with patch("drive_sync._meta_path", return_value=meta_path):
                result = drive.resolve_conflict_use_remote()

            self.assertTrue(result.get("ok"), result)
            self.assertEqual(vault.read_text(), "REMOTE_GOOD")
            self.assertFalse(conflict.exists())
            backup = Path(result["backup_path"])
            self.assertTrue(backup.exists())
            self.assertEqual(backup.read_text(), "LOCAL_OLD")


# ══════════════════════════════════════════════════════════════════════════════
# 10. Offline: local vault usable, sync fails gracefully
# ══════════════════════════════════════════════════════════════════════════════
class TestOfflineOperation(unittest.TestCase):
    def test_upload_offline_returns_offline_error(self):
        import requests as req
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            drive = _make_drive_sync(tmp_path)
            drive._creds = {"access_token": "TOKEN", "expires_at": time.time() + 3600}
            drive._user_info = {"email": "user@example.com"}
            vault = _make_civ(tmp_path / "vault.civ", "DATA")
            drive.vault_path = vault

            with patch("requests.get", side_effect=req.exceptions.ConnectionError("no network")):
                result = drive.upload(vault)

            self.assertEqual(result.get("error"), "offline")

    def test_download_offline_returns_offline_error(self):
        import requests as req
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            drive = _make_drive_sync(tmp_path)
            drive._creds = {"access_token": "TOKEN", "expires_at": time.time() + 3600}
            drive._user_info = {"email": "user@example.com"}
            vault = _make_civ(tmp_path / "vault.civ", "DATA")
            drive.vault_path = vault

            with patch("requests.get", side_effect=req.exceptions.ConnectionError("no network")):
                result = drive.download(vault)

            self.assertEqual(result.get("error"), "offline")


# ══════════════════════════════════════════════════════════════════════════════
# 11. Interrupted download does not corrupt local vault
# ══════════════════════════════════════════════════════════════════════════════
class TestAtomicDownload(unittest.TestCase):
    def test_failed_download_leaves_local_intact(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            drive = _make_drive_sync(tmp_path)
            drive._creds = {"access_token": "TOKEN", "expires_at": time.time() + 3600}
            drive._user_info = {"email": "user@example.com"}
            vault = _make_civ(tmp_path / "vault.civ", "ORIGINAL_SAFE_DATA")
            drive.vault_path = vault

            meta_path = tmp_path / ".meta.json"
            meta = {}
            meta_path.write_text(json.dumps(meta))

            folder_resp = MagicMock()
            folder_resp.raise_for_status = MagicMock()
            folder_resp.json.side_effect = [
                {"files": [{"id": "FOLDER_ID"}]},
                {"files": [{"id": "FILE_ID", "name": "vault.civ",
                            "md5Checksum": "REMOTE_MD5", "modifiedTime": "2026-01-01"}]},
            ]

            download_resp = MagicMock()
            download_resp.raise_for_status = MagicMock()
            # simulate mid-download IOError
            def bad_iter(*a, **kw):
                yield b"PARTIAL"
                raise IOError("connection reset")
            download_resp.iter_content = bad_iter

            with (
                patch("requests.get", side_effect=[folder_resp, folder_resp, download_resp]),
                patch("drive_sync._meta_path", return_value=meta_path),
            ):
                result = drive.download(vault, force=True)

            # Original vault must be unmodified
            self.assertTrue(vault.exists())
            self.assertEqual(vault.read_text(), "ORIGINAL_SAFE_DATA")
            # No .dl.tmp file left behind
            tmp_dl = vault.with_suffix(".dl.tmp")
            self.assertFalse(tmp_dl.exists())


# ══════════════════════════════════════════════════════════════════════════════
# 12. Token expiry triggers refresh
# ══════════════════════════════════════════════════════════════════════════════
class TestTokenRefresh(unittest.TestCase):
    def test_expired_token_is_refreshed_before_upload(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            drive = _make_drive_sync(tmp_path)
            drive._oauth_config = {"client_id": "ID", "client_secret": "SEC"}
            drive._creds = {
                "access_token": "OLD_TOKEN",
                "refresh_token": "REFRESH_TOKEN",
                "expires_at": time.time() - 100,   # already expired
            }
            drive._user_info = {"email": "user@example.com"}
            vault = _make_civ(tmp_path / "vault.civ", "DATA")
            drive.vault_path = vault
            meta_path = tmp_path / ".meta.json"
            meta_path.write_text("{}")

            refresh_resp = MagicMock()
            refresh_resp.raise_for_status = MagicMock()
            refresh_resp.json.return_value = {
                "access_token": "NEW_TOKEN",
                "expires_in": 3600,
            }
            folder_resp = MagicMock()
            folder_resp.raise_for_status = MagicMock()
            folder_resp.json.side_effect = [
                {"files": [{"id": "FOLDER_ID"}]},
            ]
            upload_resp = MagicMock()
            upload_resp.raise_for_status = MagicMock()
            upload_resp.json.return_value = {"id": "FILE_ID", "md5Checksum": _md5("DATA")}

            post_calls = []
            def mock_post(url, *a, **kw):
                post_calls.append(url)
                if "token" in url.lower():
                    return refresh_resp
                return upload_resp

            with (
                patch("requests.post", side_effect=mock_post),
                patch("requests.get",  return_value=folder_resp),
                patch("drive_sync._save_credentials", MagicMock()),
                patch("drive_sync._meta_path", return_value=meta_path),
            ):
                result = drive.upload(vault)

            token_refreshed = any("token" in url for url in post_calls)
            self.assertTrue(token_refreshed, "Expected token refresh call")


# ══════════════════════════════════════════════════════════════════════════════
# 13. Disconnecting Google does not delete local vault
# ══════════════════════════════════════════════════════════════════════════════
class TestDisconnect(unittest.TestCase):
    def test_disconnect_preserves_local_vault(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            drive = _make_drive_sync(tmp_path)
            drive._creds = {"access_token": "TOKEN", "expires_at": time.time() + 3600}
            drive._user_info = {"email": "user@example.com"}
            vault = _make_civ(tmp_path / "vault.civ", "PRECIOUS_DATA")
            drive.vault_path = vault

            revoke_resp = MagicMock()
            revoke_resp.raise_for_status = MagicMock()

            with (
                patch("requests.post", return_value=revoke_resp),
                patch("drive_sync._delete_credentials", MagicMock()),
            ):
                result = drive.disconnect()

            self.assertTrue(result.get("ok"))
            self.assertTrue(vault.exists(), "Local vault must NOT be deleted")
            self.assertEqual(vault.read_text(), "PRECIOUS_DATA")
            self.assertIsNone(drive._creds)
            self.assertIsNone(drive._user_info)


# ══════════════════════════════════════════════════════════════════════════════
# 14. Encryption / decryption compatibility preserved
# ══════════════════════════════════════════════════════════════════════════════
class TestEncryptionCompat(unittest.TestCase):
    def test_civ_format_unchanged(self):
        from crypto import create_vault
        vault_data, _ = create_vault("StrongMasterPassword123!!")
        required_keys = {"version", "algorithm", "salt", "kem_public_key",
                         "kem_ciphertext", "encrypted_kem_secret_key", "vault"}
        self.assertEqual(required_keys, set(vault_data.keys()))
        self.assertEqual(vault_data["version"], 1)
        self.assertIn("ML-KEM-1024", vault_data["algorithm"])

    def test_drive_sync_never_reads_plaintext(self):
        """DriveSync.upload reads raw bytes only — never decrypts."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            drive = _make_drive_sync(tmp_path)
            drive._creds = {"access_token": "TOKEN", "expires_at": time.time() + 3600}
            drive._user_info = {"email": "user@example.com"}

            vault = _make_civ(tmp_path / "vault.civ", "OPAQUE_ENCRYPTED_BYTES")
            drive.vault_path = vault
            meta_path = tmp_path / ".meta.json"
            meta_path.write_text("{}")

            uploaded_data = []
            def capture_post(url, *a, **kw):
                data = kw.get("data", b"")
                uploaded_data.append(data)
                r = MagicMock(); r.raise_for_status = MagicMock()
                r.json.return_value = {"id": "F", "md5Checksum": "x"}
                return r

            folder_get = MagicMock()
            folder_get.raise_for_status = MagicMock()
            folder_get.json.side_effect = [{"files": [{"id": "FOLDER_ID"}]}]

            with (
                patch("requests.get",  return_value=folder_get),
                patch("requests.post", side_effect=capture_post),
                patch("drive_sync._meta_path", return_value=meta_path),
            ):
                drive.upload(vault)

            combined = b"".join(uploaded_data)
            self.assertIn(b"OPAQUE_ENCRYPTED_BYTES", combined)
            # No plaintext JSON entry fields leaked
            self.assertNotIn(b"master_password", combined)
            self.assertNotIn(b"entries", combined.lower())


# ══════════════════════════════════════════════════════════════════════════════
# 15. Sync status accuracy via /api/sync/state
# ══════════════════════════════════════════════════════════════════════════════
class TestSyncStatusEndpoint(unittest.TestCase):
    def test_sync_state_returns_disconnected_with_no_creds(self):
        with (
            patch("drive_sync._load_credentials", return_value=None),
            patch("drive_sync._load_user_info",   return_value=None),
            patch("drive_sync.load_oauth_config",  return_value=None),
        ):
            import app as app_module
            client = app_module.app.test_client()
            resp = client.get("/api/sync/state")
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertFalse(data["connected"])
            self.assertIn("status", data)

    def test_sync_status_poll(self):
        import app as app_module
        client = app_module.app.test_client()
        resp = client.get("/api/sync/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("status", data)


# ══════════════════════════════════════════════════════════════════════════════
# 16. OAuth config loading
# ══════════════════════════════════════════════════════════════════════════════
class TestOAuthConfigLoading(unittest.TestCase):
    def test_load_installed_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "secrets.json"
            p.write_text(json.dumps({
                "installed": {"client_id": "ID", "client_secret": "SEC"}
            }))
            cfg = load_oauth_config(p)
            self.assertEqual(cfg["client_id"], "ID")

    def test_load_flat_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "secrets.json"
            p.write_text(json.dumps({"client_id": "ID2", "client_secret": "SEC2"}))
            cfg = load_oauth_config(p)
            self.assertEqual(cfg["client_id"], "ID2")

    def test_missing_config_returns_none(self):
        cfg = load_oauth_config(Path("/tmp/nonexistent_carbonit_config_xyz.json"))
        self.assertIsNone(cfg)

    def test_env_var_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "env_secrets.json"
            p.write_text(json.dumps({"client_id": "ENV_ID", "client_secret": "ENV_SEC"}))
            with patch.dict(os.environ, {"CARBONIT_OAUTH_CONFIG": str(p)}):
                cfg = load_oauth_config()
            self.assertEqual(cfg["client_id"], "ENV_ID")


# ══════════════════════════════════════════════════════════════════════════════
# 17. Flask API routes return correct structures
# ══════════════════════════════════════════════════════════════════════════════
class TestFlaskSyncRoutes(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.client = app_module.app.test_client()

    def test_sync_upload_requires_auth(self):
        """Upload without Google credentials returns an error, not a crash."""
        resp = self.client.post("/api/sync/upload")
        data = resp.get_json()
        self.assertIn("error", data)

    def test_sync_download_no_auth(self):
        resp = self.client.post("/api/sync/download", json={})
        data = resp.get_json()
        self.assertIn("error", data)

    def test_sync_conflict_use_local_no_auth(self):
        resp = self.client.post("/api/sync/conflict/use_local")
        data = resp.get_json()
        # Should still return a structured response
        self.assertIsInstance(data, dict)

    def test_sync_conflict_use_remote_no_conflict(self):
        resp = self.client.post("/api/sync/conflict/use_remote")
        data = resp.get_json()
        self.assertIn("error", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
