const $ = (s) => document.querySelector(s);

let entries = [];
let unlocked = false;
let authToken = null;
let inactivityTimer = null;
const AUTO_LOCK_MS = 5 * 60 * 1000; // 5 minutes

// Reset the auto-lock timer on user activity
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
  
  // If we receive a 401 Unauthorized directly from an API call, auto-lock UI
  if (res.status === 401) {
      lockVault();
      throw new Error("Session expired. Please unlock again.");
  }

  // Handle blob responses (like file exports)
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
  }
}

function showVault(data) {
  entries = data.entries || [];
  authToken = data.token; // Save our session token
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
        <button class="ghost" onclick="copyPassword('${e.id}')">Copy</button>
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

window.copyPassword = async (id) => {
  const e = entries.find(x => x.id === id);
  if (!e) return;
  await navigator.clipboard.writeText(e.password);
  resetTimer();
};

window.removeEntry = async (id) => {
  if (!confirm("Delete this credential?")) return;
  const data = await api(`/api/entries/${id}`, {method:"DELETE"});
  entries = data.entries;
  render();
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
    $("#modal").hidden = false;
    resetTimer();
};
$("#closeModal").onclick = () => $("#modal").hidden = true;
$("#search").oninput = render;

// Cryptographically secure password generator
$("#genBtn").onclick = () => {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~";
    const randomArray = new Uint32Array(16);
    crypto.getRandomValues(randomArray);
    const pass = Array.from(randomArray).map(x => chars[x % chars.length]).join('');
    $("#password").value = pass;
    $("#password").type = "text"; // temporarily reveal so user can see it
    setTimeout(() => $("#password").type = "password", 3000); // hide again after 3s
};

$("#createBtn").onclick = async () => {
  try {
    const data = await api("/api/entries", {
      method: "POST",
      body: JSON.stringify({
        name: $("#name").value,
        username: $("#username").value,
        password: $("#password").value,
        url: $("#url").value
      })
    });
    entries = data.entries;
    ["#name","#username","#password","#url"].forEach(x => $(x).value = "");
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
}

$("#lockBtn").onclick = lockVault;

init();