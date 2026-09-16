import json
import secrets
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file

from crypto import create_vault, unlock_vault, save_unlocked_vault

app = Flask(__name__)

VAULT_PATH = Path("carbonit_vault.civ")

# In-memory store mapping secure tokens to active vault states.
# This replaces Flask sessions to eliminate cookie-reset bugs.
UNLOCKED = {}


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
    VAULT_PATH.write_text(
        json.dumps(vault, indent=2),
        encoding="utf-8",
    )

    token = secrets.token_urlsafe(32)
    UNLOCKED[token] = {
        "raw": vault,
        "entries": [],
        "vault_key": vault_key,
    }

    return jsonify({"ok": True, "token": token, "entries": []})


@app.post("/api/unlock")
def unlock():
    data = request.get_json(force=True)
    password = data.get("master_password", "")

    if not VAULT_PATH.exists():
        return jsonify({"error": "No vault exists yet."}), 404

    try:
        vault, vault_key = unlock_vault(VAULT_PATH, password)
    except Exception:
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

    save_unlocked_vault(
        VAULT_PATH,
        state["raw"],
        state["entries"],
        state["vault_key"],
    )

    return jsonify({"ok": True, "entries": state["entries"]})


@app.delete("/api/entries/<entry_id>")
def delete_entry(entry_id):
    state = current_state()
    if state is None:
        return jsonify({"error": "Locked"}), 401

    state["entries"][:] = [
        x for x in state["entries"] if x["id"] != entry_id
    ]

    save_unlocked_vault(
        VAULT_PATH,
        state["raw"],
        state["entries"],
        state["vault_key"],
    )

    return jsonify({"ok": True, "entries": state["entries"]})


@app.get("/api/export")
def export_vault():
    if not VAULT_PATH.exists():
        return jsonify({"error": "No vault file exists to export."}), 404
    return send_file(VAULT_PATH, as_attachment=True, download_name="carbonit_vault.civ")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)