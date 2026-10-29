<div align="center">

# 🛡️ CarbonIt Vault

![Release](https://img.shields.io/badge/Release-V2-7c3aed?style=for-the-badge)

**A local-first desktop password manager with encrypted Google Drive sync (V2 integration)**

[![Developer](https://img.shields.io/badge/Developer-Edwin%20Sam%20K%20Reju-ffffff?labelColor=000000&logo=github&logoColor=white&style=for-the-badge)](https://edwinsamkreju.github.io/)
[![Organization](https://img.shields.io/badge/Organization-CarbonIt%20Labs-000000?labelColor=000000&logo=github&logoColor=00e5ff&style=for-the-badge)](https://github.com/CarbonIt-Labs)

![Post-quantum KEM](https://img.shields.io/badge/KEM-ML--KEM--1024-7000ff?style=flat-square)
![Key derivation](https://img.shields.io/badge/KDF-Argon2id-blue?style=flat-square)
![Encryption](https://img.shields.io/badge/Cipher-QuantCrypt%20Krypton-00a9bd?style=flat-square)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Desktop UI](https://img.shields.io/badge/Desktop-pywebview-blue.svg)](https://pywebview.flowrl.com/)

*Developed by **Edwin Sam K Reju** at [CarbonIt Labs](https://github.com/CarbonIt-Labs).*

</div>

---

## Contents

- [Overview](#overview)
- [Features](#features)
- [How the security model works](#how-the-security-model-works)
- [Requirements](#requirements)
- [Install and run from source](#install-and-run-from-source)
- [Google Drive sync setup (V2)](#google-drive-sync-setup-v2)
- [Using your vault](#using-your-vault)
- [Files and data locations](#files-and-data-locations)
- [Windows executable build](#windows-executable-build)
- [Developer notes](#developer-notes)
- [Troubleshooting](#troubleshooting)
- [Security notes and limitations](#security-notes-and-limitations)
- [License and credits](#license-and-credits)

## Overview

**CarbonIt Vault** is a desktop password manager built with Python, Flask, and `pywebview`. It stores a user's encrypted vault on the local computer. The **V2 Google Drive integration** is optional and can be used to back up or restore the encrypted vault between devices.

The application does not need a CarbonIt-hosted account or server to manage local credentials. When **V2 Google Drive sync** is enabled, the app sends the encrypted `.civ` vault file to the user's Google Drive; it does not upload the master password as part of that file.

> **V2 is optional:** Create, unlock, and manage a local vault without configuring Google OAuth or connecting Google Drive.

## Features

### Local password management

- **Create and unlock a vault** with a master password of at least 12 characters.
- **Add, edit, and delete credentials.** Each record contains a service/account name, username or email, password, and optional website URL.
- **Search credentials** by service name, username, or URL. Password values are not included in the search query.
- **Generate a password** using the browser's cryptographic random-number API. The current generator produces a 20-character value with letters, digits, and symbols.
- **Copy password or username** to the system clipboard. After 30 seconds, the app attempts to clear the clipboard only if it still contains the copied value.
- **Automatic inactivity lock** after five minutes. Mouse movement and keyboard activity reset the timer.
- **Failed-unlock delay.** After three consecutive failed unlock attempts, the app applies a 30-second lockout before another attempt can be made.
- **Encrypted `.civ` export/import** for offline backups and moving a vault to another computer.

### Optional Google Drive synchronization — V2

Every item in this section is part of **V2**. These cloud features are optional; local vault management remains available without Google sign-in.

- **[V2] Browser-based Google sign-in** using OAuth 2.0 with PKCE and a local loopback callback.
- **[V2] Background upload after a vault is created or saved**, when Drive is connected.
- **[V2] Manual sync** from the vault screen.
- **[V2] Restore on a new device** by connecting the same Google account and downloading its existing vault.
- **[V2] Sync status indicators** for states such as syncing, synced, offline, and conflict. While the vault is unlocked, the UI refreshes sync state every 15 seconds.
- **[V2] Change detection before upload** to help prevent a newer remote copy from being silently overwritten.
- **[V2] Conflict-aware download and resolution.** If a download detects different local and remote versions, the remote copy is saved separately so the user can choose which version to keep.
- **[V2] Local backup before replacement.** When an existing local vault is overwritten during a download or remote-conflict resolution, the previous file is backed up.
- **[V2] Disconnect Google** without deleting the local vault.

V2 Drive sync requires a Google OAuth client configuration; see [Google Drive sync setup (V2)](#google-drive-sync-setup-v2).

## How the security model works

The current encrypted **vault file format** is version `1`. This is separate from the **V2 application feature label** used in this README; the V2 Google/Drive integration does not by itself mean the `.civ` format is version 2. The cryptographic implementation in `crypto.py` uses the following flow:

1. **Salt generation:** a fresh random 16-byte salt is created when a vault is initialized.
2. **Master-password key derivation:** Argon2id derives a 64-byte password key using `time_cost=3`, `memory_cost=128 MiB`, and `parallelism=2`.
3. **Post-quantum key establishment:** the app uses `ML-KEM-1024` (through QuantCrypt) to create a key pair and encapsulate a shared secret. The KEM secret key is encrypted using the password-derived key.
4. **Vault-key derivation:** SHA3-512 combines the password-derived key, the KEM shared secret, and the domain-separation prefix `CARBONIT-VAULT-V1|` to derive the vault key.
5. **Vault encryption:** the credential list is serialized to JSON and encrypted with QuantCrypt's `Krypton` cipher. The encrypted vault and KEM material are stored in the `.civ` file using Base64-encoded fields.
6. **Unlock:** the app derives the password key again, decrypts the KEM secret key, decapsulates the shared secret, reconstructs the vault key, and decrypts the credential list. An incorrect password or damaged vault causes unlock to fail.

### What is stored in a `.civ` file?

The file is JSON-formatted so it can be transported and backed up, but the credential list is stored as encrypted ciphertext. Its top-level fields include the format version, algorithm label, salt, KEM public key and ciphertext, encrypted KEM secret key, and encrypted vault payload. Treat the complete `.civ` file as sensitive and keep backup copies secure.

The master password is not stored in the vault file. CarbonIt Vault does not provide a password recovery or reset mechanism: **if the master password is lost, the encrypted vault may not be recoverable.**

## Requirements

- Python **3.10 or newer**.
- `pip` and `venv` for a source installation.
- A supported `pywebview` GUI backend. On Linux, the required GTK/WebKit system packages vary by distribution; install the packages recommended by the [pywebview platform documentation](https://pywebview.flowrl.com/).
- Internet access is needed for installing dependencies and for the optional **V2 Google Drive integration**. Local vault management itself does not require a network connection.

Python dependencies are listed in [`requirements.txt`](requirements.txt), including Flask, QuantCrypt, Argon2, pywebview, Google authentication libraries (**V2**), keyring support, and `requests`.

## Install and run from source

### 1. Get the project

```bash
git clone https://github.com/CarbonIt-Labs/CarbonIt-Vault.git
cd CarbonIt-Vault
```

If you are working from a downloaded source archive instead, extract it and open a terminal in the project directory.

### 2. Create and activate a virtual environment

**Linux / macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows PowerShell**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation due to its execution policy, activate the environment using the policy approved for your machine or run the equivalent commands in Command Prompt:

```bat
.venv\Scripts\activate.bat
```

### 3. Install Python dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On Linux, if the window cannot start, check that the GUI backend and WebKit/GTK runtime dependencies required by `pywebview` are installed for your distribution.

### 4. Launch the application

```bash
python app.py
```

The desktop window opens with the CarbonIt Vault interface. On first launch, choose **Create vault** and set a strong master password containing at least 12 characters. Later launches will prompt you to unlock the existing vault.

## Google Drive sync setup (V2)

**All Google sign-in, Google Drive, OAuth, sync, and restore capabilities documented in this section are V2 features.** Google Drive sync is optional and uses your own Google Cloud OAuth client. **Do not commit OAuth client JSON files, refresh tokens, or credential backups to a public repository.**

### 1. Configure Google Cloud (V2)

1. Open the [Google Cloud Console](https://console.cloud.google.com/) and select or create a project.
2. Enable the **Google Drive API**. Follow any additional API instructions shown by the in-app setup dialog.
3. Configure the OAuth consent screen. If the application is in testing mode, add the Google account you intend to use as a test user.
4. Create an **OAuth 2.0 Client ID** with the application type **Desktop app**.
5. Download the client JSON file.

### 2. Put the JSON file in the expected location (V2)

By default, save the downloaded file as:

```text
~/.carbonit/google_client_secrets.json
```

On Windows, `~` refers to your user profile directory, so the path is typically:

```text
%USERPROFILE%\.carbonit\google_client_secrets.json
```

Create the `.carbonit` directory first if needed. The app accepts the standard Google client JSON structure (`installed` or `web`) and a flat JSON structure containing `client_id`.

Alternatively, set `CARBONIT_OAUTH_CONFIG` to the path of the client JSON file **before starting the app**.

**Linux / macOS**

```bash
export CARBONIT_OAUTH_CONFIG="$HOME/path/to/client-secrets.json"
python app.py
```

**Windows PowerShell**

```powershell
$env:CARBONIT_OAUTH_CONFIG = "C:\path\to\client-secrets.json"
python app.py
```

### 3. Connect from CarbonIt Vault (V2)

1. Click **Continue with Google** on the vault screen.
2. If the app asks for OAuth configuration, confirm the file path and click **I've done this — try again**.
3. Complete Google sign-in in the system browser and approve the requested permissions.
4. Return to CarbonIt Vault. The connected Google account should appear in the Drive panel.

The app uses a browser-based OAuth flow with PKCE and a local `127.0.0.1` callback. Its Drive integration requests the `drive.file` scope rather than unrestricted access to all files in your Drive.

### 4. Sync and restore (V2)

- Once connected, changes to the vault are uploaded in the background after a vault save. The upload runs in a background thread.
- Use **Sync** to request a manual upload of the local vault.
- To set up another computer, install CarbonIt Vault there, connect the same Google account, and choose **Restore** when the app finds a cloud vault. Unlock the restored file with the **same master password used to create it**.
- If local and remote versions differ, do not blindly replace either copy. Keep a separate backup and use the conflict options presented by the app when available.
- Select **Disconnect Google** to remove the stored Google connection. This does not delete the local vault or the cloud file.

The Drive copy is the encrypted `.civ` file. Google Drive can still expose ordinary file metadata such as the file name, size, and modification time.

## Using your vault

### Add or edit a credential

1. Unlock the vault.
2. Select **+ Add** to create a credential, or select **Edit** on an existing card.
3. Enter the service/account name and password. Username and URL are optional.
4. Use **Generate** to fill the password field with a generated 20-character password, if needed.
5. Select **Save to vault**. The updated credential list is encrypted and the vault file is saved locally.

### Search, copy, and delete

- Use the search box to filter by service name, username, or URL.
- Choose **Copy Pass** or **Copy User** on a credential card. The clipboard-clearing attempt runs after 30 seconds, but the operating system or another application may affect clipboard access.
- Choose **Delete** and confirm to remove a credential.
- Select **Lock** to return to the locked screen. The app also applies its five-minute inactivity timer.

### Export and import a vault

- **Export:** while the vault is open, select **Export** to download `carbonit_vault.civ`. This is an encrypted vault file, not a plaintext CSV.
- **Import:** on the locked screen, choose **Import existing .civ vault** and select a valid CarbonIt Vault file. Import is only accepted when no local vault currently exists at the configured default path. Move the current vault to a safe backup location before importing another one.
- After import, unlock with the master password associated with that imported vault. Importing does not merge two vaults or reset a master password.

## Files and data locations

The app creates a `.carbonit` directory under the current user's home directory.

| File | Purpose |
| --- | --- |
| `~/.carbonit/carbonit_vault.civ` | Main encrypted local vault. |
| `~/.carbonit/google_client_secrets.json` | **[V2]** Optional Google OAuth client configuration supplied by the user. |
| OS keyring entry `CarbonIt-Vault` | **[V2]** Stores Google OAuth credentials and Google account information when the keyring is available. |
| `~/.carbonit/.google_creds` | **[V2]** Fallback OAuth credential file if OS keyring storage fails; the app attempts to restrict permissions to the owner. |
| `~/.carbonit/.google_user` | **[V2]** Fallback Google account information file if OS keyring storage fails. |
| `~/.carbonit/.carbonit_sync_meta.json` | **[V2]** Sync metadata such as the Drive file ID, last-sync time, and local/remote hashes. |
| `~/.carbonit/vault_conflict_<timestamp>.civ` | **[V2]** Separate remote copy saved when a download detects a conflict. |
| `~/.carbonit/vault_backup_<timestamp>.civ` | Backup of the local vault before an operation replaces it; used by local and V2 restore/conflict workflows. |

Paths are shown in Unix notation; on Windows, replace `~` with your user profile directory. Do not manually edit the encrypted vault or sync metadata while the app is running.

## Windows executable build

Build on **Windows** to produce a Windows executable. PyInstaller is generally a per-platform build tool; running it on Linux does not produce a native Windows `.exe`.

1. Install the project dependencies in a Windows Python environment as described above.
2. Install PyInstaller into that same environment:

   ```powershell
   python -m pip install pyinstaller
   ```

3. From the project root, run:

   ```powershell
   pyinstaller --clean app.spec
   ```

The executable is generated under `dist\` (the current spec names it `app.exe`). Build with all dependencies installed in the active environment so PyInstaller can collect QuantCrypt, Argon2, Flask, pywebview, and the static/template assets.

## Developer notes

### Project layout

```text
CarbonIt-Vault/
├── app.py                 # Flask endpoints, session state, and pywebview launcher
├── crypto.py              # Vault creation, key derivation, encryption, and decryption
├── drive_sync.py          # [V2] Google OAuth, Drive upload/download, conflict handling
├── app.spec               # PyInstaller configuration for desktop packaging
├── requirements.txt       # Python dependencies
├── templates/
│   └── index.html         # Main application UI
├── static/
│   ├── app.js             # UI behavior and local API calls
│   ├── style.css          # Application styles
│   ├── logo.ico           # Application icon
│   └── logo.png           # Image asset
└── tests/
    └── test_drive_sync.py # [V2] Vault compatibility and mocked Drive-sync tests
```

### Run the tests

The **V2 Drive-sync tests** use `unittest` and mock network requests; they do not require a real Google account or real Drive upload/download operations.

```bash
python -m unittest discover -s tests -v
```

To run the same tests with pytest, install it with `python -m pip install pytest` and run:

```bash
python -m pytest tests -v
```

### Local API reference

These routes are used by the bundled frontend and are intended as implementation endpoints for the desktop app.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/status` | Check whether a local vault exists. |
| `POST` | `/api/setup` | Create a new vault. |
| `POST` | `/api/unlock` | Unlock an existing vault. |
| `POST` | `/api/lock` | Remove the current in-memory session. |
| `GET` | `/api/entries` | Read entries for the active session. |
| `POST` | `/api/entries` | Add a credential. |
| `PUT` | `/api/entries/<entry_id>` | Update a credential. |
| `DELETE` | `/api/entries/<entry_id>` | Delete a credential. |
| `GET` | `/api/export` | Download the encrypted local vault. |
| `POST` | `/api/import` | Import a `.civ` vault when no local vault exists. |
| `GET` | `/api/sync/state` | **[V2]** Get connection, status, and last-sync details. |
| `GET` | `/api/sync/status` | **[V2]** Poll the current sync status/message. |
| `POST` | `/api/sync/auth/start` | **[V2]** Start Google OAuth sign-in. |
| `POST` | `/api/sync/auth/disconnect` | **[V2]** Revoke/remove the stored Google connection. |
| `POST` | `/api/sync/upload` | **[V2]** Upload the local vault. |
| `POST` | `/api/sync/download` | **[V2]** Download the remote vault, optionally with `{"force": true}`. |
| `GET` | `/api/sync/check_remote` | **[V2]** Check for a vault in Drive without downloading it. |
| `POST` | `/api/sync/conflict/use_local` | **[V2]** Prefer and upload the local vault during conflict resolution. |
| `POST` | `/api/sync/conflict/use_remote` | **[V2]** Replace the local vault with a saved remote conflict copy. |
| `POST` | `/api/sync/oauth_config` | **[V2]** Reload the OAuth config from its configured/default location. |

## Troubleshooting

| Problem | What to check |
| --- | --- |
| The desktop window does not open on Linux | Confirm the GTK/WebKit backend required by `pywebview` is installed. Also run `python app.py` in a terminal to see startup errors. |
| **[V2]** Google sign-in says configuration is missing | Check the JSON file name and path, then click **I've done this — try again**. The default filename is `google_client_secrets.json`. |
| **[V2]** Google sign-in times out | Complete consent in the browser within the three-minute timeout. Make sure local loopback connections to `127.0.0.1` are not blocked. |
| **[V2]** Google rejects authorization | Verify the OAuth consent screen, test-user list (if the app is in testing), client type, and enabled API settings. |
| **[V2]** Restore finds no vault | Confirm that you connected the Google account used for the previous device and that a vault was uploaded to that account. |
| **[V2]** Upload is blocked because of a conflict | Another device may have changed the remote file. Avoid repeated overwrites; back up the local `.civ` file and resolve the versions deliberately. |
| A vault will not unlock | Check the master password and confirm the `.civ` file is complete and unmodified. There is no password-reset flow. |
| PyInstaller cannot find an imported package | Activate the same virtual environment in which `requirements.txt` and PyInstaller were installed, then rebuild with `--clean`. |

## Security notes and limitations

- Use a long, unique master password and keep offline backups in a secure place.
- The project has **not been independently security-audited**. Review the code and dependencies before relying on it for high-risk credentials.
- Locking the vault clears the active session from the app's session mapping and clears the displayed entries. It does **not** guarantee forensic zeroization of every secret from process memory; Python runtimes may retain copies.
- Clipboard clearing is best-effort and depends on clipboard permissions and behavior provided by the desktop environment.
- **[V2] Google Drive sync** protects the credential payload by syncing the encrypted vault file. Drive still receives file metadata such as the name, size, and modification time.
- **[V2]** Keep the OAuth configuration and fallback credential files private. Do not share them or commit them to source control.
- This project is provided without warranty; see the [MIT License](LICENSE).

## License and credits

Copyright (c) 2026 Edwin Sam K Reju.

Licensed under the [MIT License](LICENSE).
