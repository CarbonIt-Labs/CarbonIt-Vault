import json
import secrets
import time
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file

from crypto import create_vault, unlock_vault, save_unlocked_vault

app = Flask(__name__)

VAULT_PATH = Path("carbonit_vault.civ")

# In-memory session tracking & brute-force mitigation
UNLOCKED = {}
FAILED_ATTEMPTS = {"count": 0, "lockout_until": 0}


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/status")
def status():
    return jsonify({"initialized": VAULT_PATH.exists()})


def current_state():
    token = request.headers.get("X-Auth-Token")
    return UNLOCKED.get(token) if token else None


@app.post("/api/setup")
def setup():
    if VAULT_PATH.exists():
        return jsonify({"error": "Vault already exists."}), 409

    data = request.get_json(force=True)
    password = data.get("master_password", "")

    if len(password) < 12:
        return jsonify({"error": "Please use at least 12 characters for a secure CarbonIt Vault."}), 400

    vault, vault_key = create_vault(password)
    VAULT_PATH.write_text(json.dumps(vault, indent=2), encoding="utf-8")

    token = secrets.token_urlsafe(32)
    UNLOCKED[token] = {"raw": vault, "entries": [], "vault_key": vault_key}

    return jsonify({"ok": True, "token": token, "entries": []})


@app.post("/api/unlock")
def unlock():
    global FAILED_ATTEMPTS
    now = time.time()
    
    if now < FAILED_ATTEMPTS["lockout_until"]:
        wait_sec = int(FAILED_ATTEMPTS["lockout_until"] - now)
        return jsonify({"error": f"Too many failed attempts. Locked out for {wait_sec}s."}), 429

    data = request.get_json(force=True)
    password = data.get("master_password", "")

    if not VAULT_PATH.exists():
        return jsonify({"error": "No vault exists yet."}), 404

    try:
        vault, vault_key = unlock_vault(VAULT_PATH, password)
        FAILED_ATTEMPTS["count"] = 0  # Reset on success
    except Exception:
        FAILED_ATTEMPTS["count"] += 1
        if FAILED_ATTEMPTS["count"] >= 3:
            FAILED_ATTEMPTS["lockout_until"] = time.time() + 30  # 30s penalty
        return jsonify({"error": "Invalid master password or damaged vault."}), 401

    token = secrets.token_urlsafe(32)
    UNLOCKED[token] = {
        "raw": vault["raw"],
        "entries": vault["entries"],
        "vault_key": vault_key,
    }

    return jsonify({"ok": True, "token": token, "entries": vault["entries"]})


@app.post("/api/lock")
def lock():
    token = request.headers.get("X-Auth-Token")
    if token:
        UNLOCKED.pop(token, None)
    return jsonify({"ok": True})


@app.get("/api/entries")
def entries():
    state = current_state()
    if state is None:
        return jsonify({"error": "Locked"}), 401
    return jsonify({"entries": state["entries"]})


@app.post("/api/entries")
def add_entry():
    state = current_state()
    if state is None:
        return jsonify({"error": "Locked"}), 401

    data = request.get_json(force=True)
    entry = {
        "id": secrets.token_hex(8),
        "name": str(data.get("name", "")).strip(),
        "username": str(data.get("username", "")).strip(),
        "password": str(data.get("password", "")),
        "url": str(data.get("url", "")).strip(),
    }

    if not entry["name"] or not entry["password"]:
        return jsonify({"error": "Name and password are required."}), 400

    state["entries"].append(entry)
    save_unlocked_vault(VAULT_PATH, state["raw"], state["entries"], state["vault_key"])

    return jsonify({"ok": True, "entries": state["entries"]})


@app.put("/api/entries/<entry_id>")
def update_entry(entry_id):
    state = current_state()
    if state is None:
        return jsonify({"error": "Locked"}), 401

    data = request.get_json(force=True)
    target = next((x for x in state["entries"] if x["id"] == entry_id), None)
    
    if not target:
        return jsonify({"error": "Entry not found."}), 404

    target["name"] = str(data.get("name", target["name"])).strip()
    target["username"] = str(data.get("username", target["username"])).strip()
    if data.get("password"):
        target["password"] = str(data.get("password"))
    target["url"] = str(data.get("url", target["url"])).strip()

    save_unlocked_vault(VAULT_PATH, state["raw"], state["entries"], state["vault_key"])
    return jsonify({"ok": True, "entries": state["entries"]})


@app.delete("/api/entries/<entry_id>")
def delete_entry(entry_id):
    state = current_state()
    if state is None:
        return jsonify({"error": "Locked"}), 401

    state["entries"][:] = [x for x in state["entries"] if x["id"] != entry_id]
    save_unlocked_vault(VAULT_PATH, state["raw"], state["entries"], state["vault_key"])

    return jsonify({"ok": True, "entries": state["entries"]})


@app.get("/api/export")
def export_vault():
    if not VAULT_PATH.exists():
        return jsonify({"error": "No vault file exists to export."}), 404
    return send_file(VAULT_PATH, as_attachment=True, download_name="carbonit_vault.civ")


@app.post("/api/import")
def import_vault():
    if VAULT_PATH.exists():
        return jsonify({"error": "A vault already exists. Delete or move it before importing."}), 409
    
    data = request.get_json(force=True)
    if "vault" not in data or "salt" not in data:
        return jsonify({"error": "Invalid vault file format."}), 400
    
    VAULT_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return jsonify({"ok": True})


if __name__ == "__main__":
    import webview
    import ctypes
    import sys
    
    # Tell Windows this is a distinct application to fix Taskbar/Task Manager icons
    if sys.platform == "win32":
        try:
            myappid = 'carbonit.vault.app.1.0'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except Exception:
            pass
            
    webview.create_window(
        "CarbonIt Vault",
        app,
        width=1120,
        height=780,
        min_size=(800, 600),
        background_color="#07090b"
    )
    webview.start()
