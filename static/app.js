/* ── CarbonIt Vault · app.js ── */

const $ = (s) => document.querySelector(s);

// ── State ──────────────────────────────────────────────────────────────────
let entries = [];
let unlocked = false;
let authToken = null;
let inactivityTimer = null;
let syncPollTimer = null;
let lastSyncState = null;

const AUTO_LOCK_MS    = 5 * 60 * 1000;  // 5 minutes
const SYNC_POLL_MS    = 15 * 1000;       // poll every 15 s when unlocked

// ── Inactivity auto-lock ───────────────────────────────────────────────────
function resetTimer() {
  if (inactivityTimer) clearTimeout(inactivityTimer);
  if (unlocked) inactivityTimer = setTimeout(lockVault, AUTO_LOCK_MS);
}
window.addEventListener('mousemove', resetTimer);
window.addEventListener('keypress',  resetTimer);

// ── API helper ─────────────────────────────────────────────────────────────
async function api(url, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (authToken) headers["X-Auth-Token"] = authToken;

  const res = await fetch(url, { ...options, headers });

  if (res.status === 401) { lockVault(); throw new Error("Session expired. Please unlock again."); }

  if (res.headers.get("content-type")?.includes("application/octet-stream")) return res.blob();

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

// ── Escape helper ──────────────────────────────────────────────────────────
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
}

// ── Sync Status ────────────────────────────────────────────────────────────
const STATUS_LABELS = {
  idle:          "Idle",
  synced:        "Synced",
  sync_pending:  "Sync pending",
  syncing:       "Syncing…",
  offline:       "Offline",
  auth_required: "Auth required",
  conflict:      "Conflict",
  sync_failed:   "Sync failed",
  disconnected:  "Not connected",
};

function applySyncDot(dotEl, status) {
  dotEl.className = `sync-dot ${status}`;
}

function updateSyncBadge(state) {
  const badge   = $("#syncBadge");
  const dot     = $("#syncDot");
  const label   = $("#syncLabel");

  if (!state.connected) {
    badge.hidden = true;
    return;
  }

  badge.hidden = false;
  const text = STATUS_LABELS[state.status] || state.status;
  label.textContent = text;
  applySyncDot(dot, state.status);
}

function updateSyncBar(state) {
  const bar      = $("#syncBar");
  const dot      = $("#syncBarDot");
  const lbl      = $("#syncBarLabel");
  const email    = $("#syncBarEmail");
  const timeEl   = $("#syncBarTime");
  const syncBtn  = $("#syncNowBtn");

  if (!state.connected || !unlocked) {
    bar.hidden = true;
    syncBtn.hidden = true;
    return;
  }

  bar.hidden = false;
  syncBtn.hidden = false;

  const text = STATUS_LABELS[state.status] || state.status;
  lbl.textContent  = text;
  email.textContent = state.email || "";
  applySyncDot(dot, state.status);

  if (state.last_synced) {
    try {
      const d = new Date(state.last_synced);
      timeEl.textContent = "Last sync: " + d.toLocaleTimeString();
    } catch(_) { timeEl.textContent = ""; }
  } else {
    timeEl.textContent = "";
  }
}

function updateConflictBanner(state) {
  const banner = $("#conflictBanner");
  if (state.conflict && state.connected) {
    banner.hidden = false;
    const path = state.conflict_remote_path || "";
    const fname = path.split("/").pop();
    $("#conflictMsg").textContent =
      ` Remote copy saved as ${fname || "conflict file"}. Choose how to resolve:`;
  } else {
    banner.hidden = true;
  }
}

async function refreshSyncUI() {
  try {
    const state = await api("/api/sync/state");
    lastSyncState = state;
    updateSyncBadge(state);
    updateSyncBar(state);
    updateConflictBanner(state);
    updateDrivePanel(state);
  } catch (_) {}
}

// ── Drive panel (auth screen) ──────────────────────────────────────────────
function updateDrivePanel(state) {
  const disc = $("#driveDisconnected");
  const conn = $("#driveConnected");
  const restoreHint = $("#driveRestoreHint");

  if (state.connected) {
    disc.hidden = true;
    conn.hidden = false;
    $("#driveEmail").textContent = state.email || "";

    // Avatar
    if (state.picture) {
      const img = $("#driveAvatar");
      img.src = state.picture;
      img.hidden = false;
      $("#driveAvatarFallback").hidden = true;
    } else {
      $("#driveAvatar").hidden = true;
      $("#driveAvatarFallback").hidden = false;
      $("#driveAvatarFallback").textContent = (state.email || "G").charAt(0).toUpperCase();
    }
  } else {
    disc.hidden = false;
    conn.hidden = true;
    restoreHint.hidden = true;
  }
}

async function checkAndShowRestore(state) {
  if (!state.connected) return;
  if ($("#vault").hidden === false) return; // already unlocked

  const restoreHint = $("#driveRestoreHint");
  try {
    const check = await api("/api/sync/check_remote");
    if (check.exists) {
      restoreHint.hidden = false;
      const info = [];
      if (check.modified) {
        try {
          const d = new Date(check.modified);
          info.push("Modified " + d.toLocaleDateString());
        } catch(_){}
      }
      if (check.size) info.push(Math.round(check.size / 1024) + " KB");
      $("#driveRestoreInfo").textContent = info.length ? " – " + info.join(", ") : "";
    } else {
      restoreHint.hidden = true;
    }
  } catch (_) {
    restoreHint.hidden = true;
  }
}

// ── Overlay helper ─────────────────────────────────────────────────────────
function showOverlay(msg) {
  $("#syncOverlayMsg").textContent = msg;
  $("#syncOverlay").hidden = false;
}
function hideOverlay() { $("#syncOverlay").hidden = true; }

// ── Google sign-in ─────────────────────────────────────────────────────────
$("#googleSignInBtn").onclick = async () => {
  // First check config
  try {
    const cfgCheck = await api("/api/sync/state");
    if (!cfgCheck.oauth_configured) {
      $("#driveSetupModal").hidden = false;
      return;
    }
  } catch (_) {}

  showOverlay("Opening browser for Google sign-in…");
  try {
    const result = await api("/api/sync/auth/start", { method: "POST" });
    hideOverlay();
    if (result.ok) {
      await refreshSyncUI();
      if (result.remote_exists) {
        // Vault exists on Drive — show restore hint
        await checkAndShowRestore(lastSyncState || {connected: true});
      }
    } else {
      alert("Google sign-in failed: " + (result.error || "Unknown error."));
    }
  } catch(e) {
    hideOverlay();
    alert("Google sign-in error: " + e.message);
  }
};

// ── Drive Setup modal ──────────────────────────────────────────────────────
$("#closeDriveSetup").onclick = () => { $("#driveSetupModal").hidden = true; };
$("#driveSetupRefresh").onclick = async () => {
  try {
    const r = await api("/api/sync/oauth_config", { method: "POST" });
    if (r.configured) {
      $("#driveSetupModal").hidden = true;
      $("#googleSignInBtn").click();
    } else {
      alert("Configuration file not found yet. Please complete the steps above.");
    }
  } catch(e) { alert(e.message); }
};

// ── Restore (download from Drive on auth screen) ───────────────────────────
$("#driveRestoreBtn").onclick = async () => {
  const local = await api("/api/status");
  if (local.initialized) {
    // Local vault exists — use safe conflict-aware download
    showOverlay("Checking remote vault…");
    try {
      const result = await api("/api/sync/download", {
        method: "POST",
        body: JSON.stringify({ force: false })
      });
      hideOverlay();
      handleDownloadResult(result);
    } catch(e) {
      hideOverlay();
      alert("Restore failed: " + e.message);
    }
  } else {
    // No local vault — safe to download directly
    showOverlay("Downloading vault from Google Drive…");
    try {
      const result = await api("/api/sync/download", {
        method: "POST",
        body: JSON.stringify({ force: true })
      });
      hideOverlay();
      if (result.ok) {
        alert("✓ Vault restored from Google Drive!\nEnter your master password to unlock.");
        await init();
      } else {
        alert("Restore failed: " + (result.message || result.error || "Unknown error."));
      }
    } catch(e) {
      hideOverlay();
      alert("Restore failed: " + e.message);
    }
  }
};

function handleDownloadResult(result) {
  if (result.ok && result.already_synced) {
    alert("Your local vault is already up to date with Google Drive.");
  } else if (result.ok) {
    alert("✓ Vault updated from Google Drive!\nPlease unlock again.");
    lockVault();
  } else if (result.conflict) {
    refreshSyncUI();
    alert("⚠ Conflict detected!\n" + result.message);
  } else if (result.error === "no_remote") {
    alert("No vault found in Google Drive.");
  } else if (result.error === "offline") {
    alert("Offline – could not reach Google Drive.");
  } else {
    alert("Download error: " + (result.message || result.error));
  }
}

// ── Disconnect ─────────────────────────────────────────────────────────────
async function disconnectGoogle() {
  if (!confirm("Disconnect Google account?\nYour local vault will NOT be deleted.")) return;
  try {
    await api("/api/sync/auth/disconnect", { method: "POST" });
    await refreshSyncUI();
    $("#driveRestoreHint").hidden = true;
  } catch(e) { alert("Disconnect error: " + e.message); }
}
$("#driveDisconnectBtnAuth").onclick  = disconnectGoogle;
$("#driveDisconnectBtnVault").onclick = disconnectGoogle;

// ── Sync Now ───────────────────────────────────────────────────────────────
$("#syncNowBtn").onclick = async () => {
  try {
    const r = await api("/api/sync/upload", { method: "POST" });
    if (r.error === "conflict") {
      alert("⚠ Upload blocked:\n" + r.message);
    } else if (!r.ok) {
      alert("Sync failed: " + (r.error || "Unknown."));
    }
    await refreshSyncUI();
  } catch(e) { alert("Sync error: " + e.message); }
};

// ── Conflict resolution ────────────────────────────────────────────────────
$("#useLocalBtn").onclick = async () => {
  if (!confirm("Upload your local vault and discard the remote conflict copy?")) return;
  showOverlay("Uploading local vault…");
  try {
    const r = await api("/api/sync/conflict/use_local", { method: "POST" });
    hideOverlay();
    if (r.ok) { await refreshSyncUI(); }
    else alert("Error: " + r.error);
  } catch(e) { hideOverlay(); alert(e.message); }
};

$("#useRemoteBtn").onclick = async () => {
  if (!confirm("Replace local vault with the cloud version?\nYour current local vault will be backed up.")) return;
  showOverlay("Applying remote vault…");
  try {
    const r = await api("/api/sync/conflict/use_remote", { method: "POST" });
    hideOverlay();
    if (r.ok) {
      alert("Remote vault applied. Your old local vault was backed up.\nPlease unlock again.");
      await lockVault();
    } else {
      alert("Error: " + r.error);
    }
    await refreshSyncUI();
  } catch(e) { hideOverlay(); alert(e.message); }
};

// ── Vault unlock / create ──────────────────────────────────────────────────
async function init() {
  const s = await api("/api/status");
  if (!s.initialized) {
    $("#authTitle").textContent = "Create CarbonIt Vault";
    $("#authHint").textContent   = "Choose a strong master password. Your vault is stored locally.";
    $("#authBtn").textContent    = "Create vault";
    $("#dividerOr").querySelector("span").textContent = "or create with master password";
  } else {
    $("#authTitle").textContent = "Unlock your vault";
    $("#authHint").textContent  = "Your master password never leaves this local app.";
    $("#authBtn").textContent   = "Unlock";
    $("#dividerOr").querySelector("span").textContent = "or unlock with master password";
  }
  await refreshSyncUI();
  if (lastSyncState?.connected) await checkAndShowRestore(lastSyncState);
}

function showVault(data) {
  entries    = data.entries || [];
  authToken  = data.token;
  unlocked   = true;
  $("#auth").hidden  = false; // keep hidden below
  $("#auth").hidden  = true;
  $("#vault").hidden = false;
  $("#status").textContent = "UNLOCKED";
  resetTimer();
  startSyncPoll();
  refreshSyncUI();
  render();
}

async function lockVault() {
  if (authToken) await api("/api/lock", { method: "POST" }).catch(() => {});
  entries       = [];
  authToken     = null;
  unlocked      = false;
  if (inactivityTimer) clearTimeout(inactivityTimer);
  stopSyncPoll();
  $("#vault").hidden  = true;
  $("#modal").hidden  = true;
  $("#auth").hidden   = false;
  $("#status").textContent = "LOCKED";
  await init();
}

// ── Sync polling (runs while unlocked) ────────────────────────────────────
function startSyncPoll() {
  stopSyncPoll();
  syncPollTimer = setInterval(refreshSyncUI, SYNC_POLL_MS);
}
function stopSyncPoll() {
  if (syncPollTimer) { clearInterval(syncPollTimer); syncPollTimer = null; }
}

// ── Auth button ────────────────────────────────────────────────────────────
$("#authBtn").onclick = async () => {
  $("#authError").textContent = "";
  const password = $("#master").value;
  try {
    const status = await api("/api/status");
    const endpoint = status.initialized ? "/api/unlock" : "/api/setup";
    const data = await api(endpoint, {
      method: "POST",
      body: JSON.stringify({ master_password: password })
    });
    $("#master").value = "";
    showVault(data);
  } catch(e) {
    $("#authError").textContent = e.message;
  }
};

// ── Render credentials ─────────────────────────────────────────────────────
function render() {
  const q    = $("#search").value.toLowerCase();
  const list = entries.filter(e =>
    `${e.name} ${e.username} ${e.url}`.toLowerCase().includes(q)
  );

  $("#empty").hidden = list.length !== 0;
  $("#entries").innerHTML = list.map(e => `
    <article class="entry">
      <h3>${escapeHtml(e.name)}</h3>
      <div class="url">${escapeHtml(e.url || "")}</div>
      <div class="user">${escapeHtml(e.username || "")}</div>
      <div class="secret">••••••••••</div>
      <div class="entry-actions">
        <button class="ghost" onclick="copyField('${e.id}','password')">Copy Pass</button>
        <button class="ghost" onclick="copyField('${e.id}','username')">Copy User</button>
        <button class="ghost" onclick="openEditModal('${e.id}')">Edit</button>
        <button class="danger" onclick="removeEntry('${e.id}')">Delete</button>
      </div>
    </article>
  `).join("");
}

// ── Copy field ─────────────────────────────────────────────────────────────
window.copyField = async (id, field) => {
  const e = entries.find(x => x.id === id);
  if (!e) return;
  const val = field === 'password' ? e.password : e.username;
  if (!val) { alert("No " + field + " available."); return; }
  await navigator.clipboard.writeText(val);
  resetTimer();
  setTimeout(async () => {
    try {
      const clip = await navigator.clipboard.readText();
      if (clip === val) await navigator.clipboard.writeText("");
    } catch(_) {}
  }, 30000);
};

// ── Remove entry ───────────────────────────────────────────────────────────
window.removeEntry = async (id) => {
  if (!confirm("Delete this credential?")) return;
  const data = await api(`/api/entries/${id}`, { method: "DELETE" });
  entries = data.entries;
  render();
};

// ── Edit modal ─────────────────────────────────────────────────────────────
window.openEditModal = (id) => {
  const e = entries.find(x => x.id === id);
  if (!e) return;
  $("#editId").value   = e.id;
  $("#modalTitle").textContent = "Edit credential";
  $("#name").value     = e.name;
  $("#username").value = e.username;
  $("#password").value = e.password;
  $("#url").value      = e.url;
  $("#modal").hidden   = false;
  resetTimer();
};

$("#addBtn").onclick = () => {
  $("#editId").value = "";
  $("#modalTitle").textContent = "Add credential";
  ["#name","#username","#password","#url"].forEach(x => $(x).value = "");
  $("#modal").hidden = false;
  resetTimer();
};
$("#closeModal").onclick = () => { $("#modal").hidden = true; };
$("#search").oninput = render;

// ── Generate password ──────────────────────────────────────────────────────
$("#genBtn").onclick = () => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~";
  const rnd   = new Uint32Array(20);
  crypto.getRandomValues(rnd);
  const pass  = Array.from(rnd).map(x => chars[x % chars.length]).join("");
  $("#password").value = pass;
  $("#password").type  = "text";
  setTimeout(() => { $("#password").type = "password"; }, 3000);
};

// ── Save entry ─────────────────────────────────────────────────────────────
$("#saveEntryBtn").onclick = async () => {
  try {
    const editId   = $("#editId").value;
    const endpoint = editId ? `/api/entries/${editId}` : "/api/entries";
    const method   = editId ? "PUT" : "POST";
    const data = await api(endpoint, {
      method,
      body: JSON.stringify({
        name:     $("#name").value,
        username: $("#username").value,
        password: $("#password").value,
        url:      $("#url").value,
      })
    });
    entries = data.entries;
    ["#name","#username","#password","#url","#editId"].forEach(x => $(x).value = "");
    $("#modal").hidden = true;
    render();
  } catch(e) { alert(e.message); }
};

// ── Export ────────────────────────────────────────────────────────────────
$("#exportBtn").onclick = async () => {
  try {
    const blob = await api("/api/export", { method: "GET" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = "carbonit_vault.civ";
    document.body.appendChild(a); a.click();
    URL.revokeObjectURL(url);
  } catch(e) { alert("Export failed: " + e.message); }
};

// ── Import ────────────────────────────────────────────────────────────────
async function handleImportFile(file) {
  try {
    const text        = await file.text();
    const jsonContent = JSON.parse(text);
    const res = await api("/api/import", {
      method: "POST",
      body: JSON.stringify(jsonContent)
    });
    if (res.ok) { alert("Vault imported! Please unlock."); window.location.reload(); }
  } catch(e) { alert("Import failed: " + e.message); }
}
$("#importVaultBtn").onclick = () => { $("#importFile").click(); };
$("#importFile").onchange    = (e) => { if (e.target.files[0]) handleImportFile(e.target.files[0]); };
$("#importBtn").onclick      = () => { $("#importFileUnlocked").click(); };
$("#importFileUnlocked").onchange = (e) => { if (e.target.files[0]) handleImportFile(e.target.files[0]); };

// ── Lock ──────────────────────────────────────────────────────────────────
$("#lockBtn").onclick = lockVault;

// ── Boot ──────────────────────────────────────────────────────────────────
init();