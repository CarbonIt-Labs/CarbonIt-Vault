const $ = (s) => document.querySelector(s);

let entries = [];
let unlocked = false;
let authToken = null;
let inactivityTimer = null;
const AUTO_LOCK_MS = 5 * 60 * 1000; // 5 minutes

function resetTimer() {
  if (inactivityTimer) clearTimeout(inactivityTimer);
  if (unlocked) {
    inactivityTimer = setTimeout(() => lockVault(), AUTO_LOCK_MS);
  }
}

window.addEventListener('mousemove', resetTimer);
window.addEventListener('keypress', resetTimer);

async function api(url, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };
  
  if (authToken) {
    headers["X-Auth-Token"] = authToken;
  }

  const res = await fetch(url, { ...options, headers });
  
  if (res.status === 401) {
      lockVault();
      throw new Error("Session expired. Please unlock again.");
  }

  if (res.headers.get("content-type")?.includes("application/octet-stream")) {
    return res.blob();
  }

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

async function init() {
  const s = await api("/api/status");
  if (!s.initialized) {
    $("#authTitle").textContent = "Create CarbonIt Vault";
    $("#authHint").textContent = "Choose a strong master password. This app stores your encrypted vault locally.";
    $("#authBtn").textContent = "Create vault";
  } else {
    $("#authTitle").textContent = "Unlock your vault";
    $("#authHint").textContent = "Your master password never leaves this local app.";
    $("#authBtn").textContent = "Unlock";
  }
}

function showVault(data) {
  entries = data.entries || [];
  authToken = data.token;
  unlocked = true;
  $("#auth").hidden = true;
  $("#vault").hidden = false;
  $("#status").textContent = "UNLOCKED";
  resetTimer();
  render();
}

function render() {
  const q = $("#search").value.toLowerCase();
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
        <button class="ghost" onclick="copyField('${e.id}', 'password')">Copy Pass</button>
        <button class="ghost" onclick="copyField('${e.id}', 'username')">Copy User</button>
        <button class="ghost" onclick="openEditModal('${e.id}')">Edit</button>
        <button class="danger" onclick="removeEntry('${e.id}')">Delete</button>
      </div>
    </article>
  `).join("");
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
  }[c]));
}

window.copyField = async (id, field) => {
  const e = entries.find(x => x.id === id);
  if (!e) return;
  const val = field === 'password' ? e.password : e.username;
  if (!val) {
    alert("No " + field + " available.");
    return;
  }
  await navigator.clipboard.writeText(val);
  resetTimer();
  
  setTimeout(async () => {
    try {
      const currentClip = await navigator.clipboard.readText();
      if (currentClip === val) {
        await navigator.clipboard.writeText("");
      }
    } catch (err) {}
  }, 30000);
};

window.removeEntry = async (id) => {
  if (!confirm("Delete this credential?")) return;
  const data = await api(`/api/entries/${id}`, {method:"DELETE"});
  entries = data.entries;
  render();
};

window.openEditModal = (id) => {
  const e = entries.find(x => x.id === id);
  if (!e) return;
  $("#editId").value = e.id;
  $("#modalTitle").textContent = "Edit credential";
  $("#name").value = e.name;
  $("#username").value = e.username;
  $("#password").value = e.password;
  $("#url").value = e.url;
  $("#modal").hidden = false;
  resetTimer();
};

$("#authBtn").onclick = async () => {
  $("#authError").textContent = "";
  const password = $("#master").value;
  try {
    const status = await api("/api/status");
    const endpoint = status.initialized ? "/api/unlock" : "/api/setup";
    const data = await api(endpoint, {
      method: "POST",
      body: JSON.stringify({master_password: password})
    });
    $("#master").value = "";
    showVault(data);
  } catch (e) {
    $("#authError").textContent = e.message;
  }
};

$("#addBtn").onclick = () => {
    $("#editId").value = "";
    $("#modalTitle").textContent = "Add credential";
    ["#name","#username","#password","#url"].forEach(x => $(x).value = "");
    $("#modal").hidden = false;
    resetTimer();
};
$("#closeModal").onclick = () => $("#modal").hidden = true;
$("#search").oninput = render;

$("#genBtn").onclick = () => {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~";
    const randomArray = new Uint32Array(16);
    crypto.getRandomValues(randomArray);
    const pass = Array.from(randomArray).map(x => chars[x % chars.length]).join('');
    $("#password").value = pass;
    $("#password").type = "text";
    setTimeout(() => $("#password").type = "password", 3000);
};

$("#saveEntryBtn").onclick = async () => {
  try {
    const editId = $("#editId").value;
    const endpoint = editId ? `/api/entries/${editId}` : "/api/entries";
    const method = editId ? "PUT" : "POST";

    const data = await api(endpoint, {
      method: method,
      body: JSON.stringify({
        name: $("#name").value,
        username: $("#username").value,
        password: $("#password").value,
        url: $("#url").value
      })
    });
    entries = data.entries;
    ["#name","#username","#password","#url","#editId"].forEach(x => $(x).value = "");
    $("#modal").hidden = true;
    render();
  } catch (e) {
    alert(e.message);
  }
};

$("#exportBtn").onclick = async () => {
    try {
        const blob = await api("/api/export", { method: "GET" });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "carbonit_vault.civ";
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
    } catch (e) {
        alert("Failed to export vault: " + e.message);
    }
};

async function handleImportFile(file) {
    try {
        const text = await file.text();
        const jsonContent = JSON.parse(text);
        const res = await api("/api/import", {
            method: "POST",
            body: JSON.stringify(jsonContent)
        });
        if (res.ok) {
            alert("Vault imported successfully! Please unlock your vault.");
            window.location.reload();
        }
    } catch (e) {
        alert("Import failed: " + e.message);
    }
}

$("#importVaultBtn").onclick = () => $("#importFile").click();
$("#importFile").onchange = (e) => {
    if (e.target.files[0]) handleImportFile(e.target.files[0]);
};

$("#importBtn").onclick = () => $("#importFileUnlocked").click();
$("#importFileUnlocked").onchange = (e) => {
    if (e.target.files[0]) handleImportFile(e.target.files[0]);
};

async function lockVault() {
  if (authToken) {
      await api("/api/lock", {method:"POST"}).catch(() => {});
  }
  entries = [];
  authToken = null;
  unlocked = false;
  if (inactivityTimer) clearTimeout(inactivityTimer);
  $("#vault").hidden = true;
  $("#modal").hidden = true;
  $("#auth").hidden = false;
  $("#status").textContent = "LOCKED";
  
  // Re-verify status so title and button correctly show "Unlock" instead of "Create"
  await init();
}

$("#lockBtn").onclick = lockVault;

init();