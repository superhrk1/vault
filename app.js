/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
   VAULT â€” app.js
   AES-256-GCM encryption Â· PBKDF2 key derivation
   Google Drive OAuth2 sync Â· Full offline PWA
   â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

"use strict";

// â”€â”€ Shortcuts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const $ = id => document.getElementById(id);
const enc = s  => new TextEncoder().encode(s);
const dec = b  => new TextDecoder().decode(b);
const rnd = n  => crypto.getRandomValues(new Uint8Array(n));
const b64e = u => btoa(String.fromCharCode(...u));
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const esc  = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
const sleep = ms => new Promise(r => setTimeout(r, ms));

// â”€â”€ LS wrapper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const LS = {
  get : k  => { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
  set : (k,v) => localStorage.setItem(k, JSON.stringify(v)),
  del : k  => localStorage.removeItem(k),
};

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  CRYPTO  (AES-256-GCM + PBKDF2)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const Crypto = {
  async deriveKey(password, salt) {
    const ITERS = VAULT_CONFIG.PBKDF2_ITERATIONS || 310000;
    const mat = await crypto.subtle.importKey("raw", enc(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name:"PBKDF2", salt, iterations:ITERS, hash:"SHA-256" },
      mat, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]
    );
  },

  async encrypt(data, password) {
    const salt = rnd(16), iv = rnd(12);
    const key  = await Crypto.deriveKey(password, salt);
    const ct   = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, enc(JSON.stringify(data)));
    const buf  = new Uint8Array(16 + 12 + ct.byteLength);
    buf.set(salt, 0); buf.set(iv, 16); buf.set(new Uint8Array(ct), 28);
    return b64e(buf);
  },

  async decrypt(b64, password) {
    const buf  = b64d(b64);
    const salt = buf.slice(0, 16), iv = buf.slice(16, 28), ct = buf.slice(28);
    const key  = await Crypto.deriveKey(password, salt);
    const pt   = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, key, ct);
    return JSON.parse(dec(pt));
  },

  async hashPassword(password) {
    const buf = await crypto.subtle.digest("SHA-256", enc(password + "__vault_kdf_2024__"));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("");
  },
};

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  STATE
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
let STATE = {
  masterKey        : null,
  items            : [],
  tab              : "all",
  favOnly          : false,
  activeTags       : [],
  sort             : "urgency",   // urgency | name | name-d | new | old | type
  expandedId       : null,
  pwVisible        : {},
  editId           : null,
  mTags            : [],
  mType            : "password",
  mPriority        : "high",
  genOpts          : { upper:true, lower:true, num:true, sym:true },
  drive: {
    token     : null,
    fileId    : null,
    status    : "offline",
    lastSync  : null,
  }
};

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  STORAGE  â€” only encrypted blobs ever hit localStorage
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function persistItems() {
  if (!STATE.masterKey) return;
  if (!STATE.items.length) { LS.del("vault_data"); return; }
  const blob = await Crypto.encrypt(STATE.items, STATE.masterKey);
  LS.set("vault_data", blob);
}

async function loadItems() {
  const blob = LS.get("vault_data");
  if (!blob) { STATE.items = []; return; }
  try { STATE.items = await Crypto.decrypt(blob, STATE.masterKey); }
  catch { STATE.items = []; }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  BOOT
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function boot() {
  // Register SW
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  }

  // Handle OAuth redirect (token in URL hash)
  handleOAuthCallback();

  // Restore drive state
  STATE.drive.token  = LS.get("drive_token");
  STATE.drive.fileId = LS.get("drive_file_id");
  STATE.drive.lastSync = LS.get("drive_last_sync");

  // Detect if Client ID is configured
  const configured = VAULT_CONFIG.GOOGLE_CLIENT_ID &&
    !VAULT_CONFIG.GOOGLE_CLIENT_ID.startsWith("PASTE_");
  STATE.drive.status = configured ? (STATE.drive.token ? "synced" : "offline") : "noconfig";

  // Show vault exists or first-run
  const hasVault = !!LS.get("vault_hash");
  if (!hasVault) {
    $("lock-hint").textContent = "First time? Set your master password below.";
    $("lock-setup-btn").style.display = "block";
    $("lock-main-btn").textContent = "Create Vault";
  }
  $("lock-inp").addEventListener("keydown", e => { if (e.key === "Enter") handleLock(); });
  renderSyncBadge();
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  LOCK / UNLOCK
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function handleLock() {
  const pw = $("lock-inp").value;
  setLockErr("");
  if (!pw) { setLockErr("Enter your password"); return; }
  const hasVault = !!LS.get("vault_hash");
  if (!hasVault) { await setupVault(pw); return; }
  const hash = await Crypto.hashPassword(pw);
  if (hash !== LS.get("vault_hash")) {
    setLockErr("Wrong password âŒ");
    $("lock-inp").classList.add("shake");
    setTimeout(() => $("lock-inp").classList.remove("shake"), 500);
    return;
  }
  STATE.masterKey = pw;
  await loadItems();
  openApp();
}

async function setupVault(pw) {
  if (pw.length < 4) { setLockErr("Min 4 characters"); return; }
  const hash = await Crypto.hashPassword(pw);
  LS.set("vault_hash", hash);
  STATE.masterKey = pw;
  STATE.items = [];
  openApp();
}

function openApp() {
  $("lock").classList.add("gone");
  renderAll();
  updateStats();
  renderDrivePanel();
  // Show Drive banner if not configured or not connected
  const configured = VAULT_CONFIG.GOOGLE_CLIENT_ID && !VAULT_CONFIG.GOOGLE_CLIENT_ID.startsWith("PASTE_");
  if (!STATE.drive.token && !LS.get("drive_banner_dismissed")) {
    $("drive-banner").classList.add("show");
    $("db-msg").textContent = configured
      ? "Connect Google Drive to sync your vault across devices"
      : "âš™ï¸ Add your Google Client ID in config.js to enable Drive sync";
  }
}

function lockVault() {
  STATE.masterKey = null;
  STATE.items     = [];
  STATE.expandedId = null;
  STATE.pwVisible  = {};
  $("lock").classList.remove("gone");
  $("lock-inp").value = "";
  setLockErr("");
}

function setLockErr(msg) { $("lock-err").textContent = msg; }
function toggleLockEye() {
  const inp = $("lock-inp");
  inp.type = inp.type === "password" ? "text" : "password";
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  GOOGLE DRIVE â€” OAuth2 implicit flow
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function handleOAuthCallback() {
  const hash = location.hash;
  if (!hash.includes("access_token")) return;
  const params = new URLSearchParams(hash.slice(1));
  const token  = params.get("access_token");
  if (!token) return;
  STATE.drive.token = token;
  LS.set("drive_token", token);
  // Clean URL
  history.replaceState(null, "", location.pathname);
}

function connectDrive() {
  const clientId = VAULT_CONFIG.GOOGLE_CLIENT_ID;
  if (!clientId || clientId.startsWith("PASTE_")) {
    toast("Add your Client ID to config.js first â€” see SETUP.md");
    return;
  }
  const redirectUri = location.origin + location.pathname;
  const params = new URLSearchParams({
    client_id    : clientId,
    redirect_uri : redirectUri,
    response_type: "token",
    scope        : VAULT_CONFIG.DRIVE_SCOPE,
    prompt       : "select_account",
  });
  // Try popup first; fall back to redirect (mobile)
  const authUrl = "https://accounts.google.com/o/oauth2/v2/auth?" + params;
  const popup = window.open(authUrl, "gdrive_auth", "width=520,height=620,left=120,top=80");
  if (!popup || popup.closed) {
    // Mobile: redirect instead of popup
    location.href = authUrl;
    return;
  }
  // Poll for redirect result in popup
  const poll = setInterval(() => {
    try {
      if (!popup || popup.closed) { clearInterval(poll); return; }
      const h = popup.location.hash;
      if (h && h.includes("access_token")) {
        clearInterval(poll);
        const p = new URLSearchParams(h.slice(1));
        STATE.drive.token  = p.get("access_token");
        LS.set("drive_token", STATE.drive.token);
        popup.close();
        toast("Google Drive connected âœ“");
        renderDrivePanel();
        renderSyncBadge();
        triggerSync();
      }
    } catch { /* cross-origin until redirect */ }
  }, 500);
}

function disconnectDrive() {
  STATE.drive.token  = null;
  STATE.drive.fileId = null;
  STATE.drive.status = "offline";
  LS.del("drive_token");
  LS.del("drive_file_id");
  LS.del("drive_last_sync");
  renderDrivePanel();
  renderSyncBadge();
  toast("Drive disconnected");
}

async function driveReq(url, opts = {}) {
  const res = await fetch(url, {
    ...opts,
    headers: {
      "Authorization": "Bearer " + STATE.drive.token,
      ...(opts.headers || {}),
    },
  });
  if (res.status === 401) {
    // Token expired
    STATE.drive.token = null;
    LS.del("drive_token");
    STATE.drive.status = "error";
    renderSyncBadge();
    renderDrivePanel();
    throw new Error("SESSION_EXPIRED");
  }
  return res;
}

async function triggerSync() {
  if (!STATE.drive.token) { toast("Connect Drive first"); return; }
  if (!STATE.masterKey) return;
  setSyncStatus("syncing");
  try {
    await uploadVault();
    const now = new Date().toISOString();
    STATE.drive.lastSync = now;
    LS.set("drive_last_sync", now);
    setSyncStatus("synced");
    toast("Synced to Drive âœ“");
    renderDrivePanel();
  } catch (e) {
    setSyncStatus("error");
    if (e.message === "SESSION_EXPIRED") toast("Drive session expired â€” reconnect");
    else toast("Sync failed: " + e.message);
  }
}

async function uploadVault() {
  const encrypted = await Crypto.encrypt(STATE.items, STATE.masterKey);
  const payload   = JSON.stringify({
    version  : 2,
    app      : "vault-pwa",
    exported : new Date().toISOString(),
    vault    : encrypted,
  });

  // Find or create file
  if (!STATE.drive.fileId) {
    const q   = encodeURIComponent(`name='${VAULT_CONFIG.DRIVE_FILE_NAME}' and trashed=false`);
    const res = await driveReq(`https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id)`);
    const dat = await res.json();
    if (dat.files?.length) {
      STATE.drive.fileId = dat.files[0].id;
      LS.set("drive_file_id", STATE.drive.fileId);
    }
  }

  if (STATE.drive.fileId) {
    // Update
    await driveReq(
      `https://www.googleapis.com/upload/drive/v3/files/${STATE.drive.fileId}?uploadType=media`,
      { method:"PATCH", headers:{"Content-Type":"application/json"}, body:payload }
    );
  } else {
    // Create
    const meta = { name:VAULT_CONFIG.DRIVE_FILE_NAME, mimeType:"application/json" };
    const form = new FormData();
    form.append("metadata", new Blob([JSON.stringify(meta)], { type:"application/json" }));
    form.append("file",     new Blob([payload],              { type:"application/json" }));
    const res = await driveReq(
      "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id",
      { method:"POST", body:form }
    );
    const dat = await res.json();
    STATE.drive.fileId = dat.id;
    LS.set("drive_file_id", STATE.drive.fileId);
  }
}

async function pullFromDrive() {
  if (!STATE.drive.token) { toast("Connect Drive first"); return; }
  setSyncStatus("syncing");
  try {
    let fileId = STATE.drive.fileId;
    if (!fileId) {
      const q   = encodeURIComponent(`name='${VAULT_CONFIG.DRIVE_FILE_NAME}' and trashed=false`);
      const res = await driveReq(`https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id)`);
      const dat = await res.json();
      if (!dat.files?.length) { toast("No backup found on Drive"); setSyncStatus("synced"); return; }
      fileId = dat.files[0].id;
      STATE.drive.fileId = fileId;
      LS.set("drive_file_id", fileId);
    }
    const res     = await driveReq(`https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`);
    const payload = await res.json();
    if (!payload.vault) throw new Error("Invalid backup");
    const imported = await Crypto.decrypt(payload.vault, STATE.masterKey);
    let added = 0;
    for (const item of imported) {
      if (!STATE.items.find(i => i.id === item.id)) { STATE.items.push(item); added++; }
    }
    await persistItems();
    renderAll(); updateStats();
    setSyncStatus("synced");
    const now = new Date().toISOString();
    STATE.drive.lastSync = now; LS.set("drive_last_sync", now);
    toast(`Pulled ${added} new items from Drive âœ“`);
    renderDrivePanel();
  } catch (e) {
    setSyncStatus("error");
    if (e.message === "SESSION_EXPIRED") toast("Drive session expired â€” reconnect");
    else toast("Pull failed: " + e.message);
  }
}

function setSyncStatus(s) {
  STATE.drive.status = s;
  renderSyncBadge();
}

function renderSyncBadge() {
  const badge = $("sync-badge");
  const label = $("sync-label");
  const s = STATE.drive.status;
  badge.className = "sync-badge " + s;
  const map = { offline:"Local", syncing:"Syncingâ€¦", synced:"Drive âœ“", error:"Sync Error", noconfig:"No Drive" };
  label.textContent = map[s] || s;
}

function renderDrivePanel() {
  const panel = $("drive-panel");
  if (!panel) return;
  const { token, lastSync, status } = STATE.drive;
  const configured = VAULT_CONFIG.GOOGLE_CLIENT_ID && !VAULT_CONFIG.GOOGLE_CLIENT_ID.startsWith("PASTE_");
  const syncTime   = lastSync ? new Date(lastSync).toLocaleString() : "Never";

  if (!configured) {
    panel.innerHTML = driveRow("âš™ï¸","Not configured","Add your Client ID to config.js â€” see SETUP.md","","");
    return;
  }

  if (token) {
    panel.innerHTML =
      driveRow("â˜ï¸","Google Drive","Connected Â· Last sync: "+syncTime,
        `<span class="dr-act sync" onclick="triggerSync()">Sync Now</span>`) +
      driveRow("â¬‡ï¸","Pull from Drive","Merge cloud backup into local vault",
        `<span class="dr-act pull" onclick="pullFromDrive()">Pull</span>`) +
      driveRow("ðŸ”Œ","Disconnect","Remove Drive access",
        `<span class="dr-act disc" onclick="disconnectDrive()">Remove</span>`);
  } else {
    panel.innerHTML =
      driveRow("â˜ï¸","Google Drive","Not connected Â· Sync vault across devices",
        `<span class="dr-act connect" onclick="connectDrive()">Connect</span>`);
  }
}

function driveRow(ico, name, sub, action="") {
  return `<div class="dr-row">
    <div class="dr-ico">${ico}</div>
    <div class="dr-info"><div class="dr-name">${name}</div><div class="dr-sub">${sub}</div></div>
    ${action}
  </div>`;
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  ITEMS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

async function saveItem(item) {
  const idx = STATE.items.findIndex(i => i.id === item.id);
  if (idx >= 0) STATE.items[idx] = item; else STATE.items.push(item);
  await persistItems();
  if (STATE.drive.token) triggerSync();
}

async function removeItem(id) {
  STATE.items = STATE.items.filter(i => i.id !== id);
  await persistItems();
  if (STATE.drive.token) triggerSync();
  renderAll(); updateStats();
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  RENDER â€” LIST
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
const T_ICON  = { password:"ðŸ”‘", bookmark:"ðŸ”–", note:"ðŸ“", subscription:"ðŸ’³" };
const T_CLASS = { password:"ip", bookmark:"ib", note:"in", subscription:"is" };

function getAllTags() {
  const s = new Set();
  STATE.items.forEach(i => (i.tags||[]).forEach(t => s.add(t)));
  return [...s].sort();
}

function toggleFavFilter() {
  STATE.favOnly = !STATE.favOnly;
  $("fav-btn").classList.toggle("on", STATE.favOnly);
  renderList();
}

function switchTab(el, t) {
  STATE.tab = t;
  document.querySelectorAll(".tab").forEach(e => e.classList.remove("on"));
  el.classList.add("on");
  renderList();
}

function onSearch(inp) {
  $("q-clear").style.display = inp.value ? "block" : "none";
  renderList();
}
function clearSearch() {
  $("q").value = "";
  $("q-clear").style.display = "none";
  renderList();
}

// Returns urgency score (lower = more urgent) for smart home sort
function getItemUrgency(item) {
  const fd = item.flagDate;
  if (fd) {
    const days = (new Date(fd).getTime() - Date.now()) / 86400000;
    if (days < 0)   return 0;   // expired
    if (days < 1)   return 1;   // today
    if (days < 3)   return 2;   // very soon
    if (days < 7)   return 3;   // soon
    if (days < 30)  return 4;   // upcoming
  }
  if (item.priority === "high") return 5;
  return 6;
}

function filtered() {
  const q = ($("q")?.value || "").toLowerCase();
  let r = STATE.items.filter(i => {
    if (STATE.tab !== "all" && i.type !== STATE.tab) return false;
    if (STATE.favOnly && !i.fav) return false;
    // Multi-tag: item must match ANY selected tag
    if (STATE.activeTags.length > 0 && !STATE.activeTags.some(t => (i.tags||[]).includes(t))) return false;
    if (!q) return true;
    return [i.title, i.username, i.url, i.note, ...(i.tags||[])].some(v => (v||"").toLowerCase().includes(q));
  });
  // Sort
  if (STATE.sort === "urgency" || !STATE.sort) {
    r.sort((a, b) => {
      const diff = getItemUrgency(a) - getItemUrgency(b);
      return diff !== 0 ? diff : (b.created||0) - (a.created||0);
    });
  } else if (STATE.sort === "name")   r.sort((a,b) => (a.title||"").localeCompare(b.title||""));
  else if (STATE.sort === "name-d")   r.sort((a,b) => (b.title||"").localeCompare(a.title||""));
  else if (STATE.sort === "new")      r.sort((a,b) => b.created - a.created);
  else if (STATE.sort === "old")      r.sort((a,b) => a.created - b.created);
  else if (STATE.sort === "type")     r.sort((a,b) => (a.type||"").localeCompare(b.type||""));
  return r;
}

function renderList() {
  const area = $("list");
  const list = filtered();
  if (!list.length) {
    const icons = { all:"ðŸ”", password:"ðŸ”‘", subscription:"ðŸ’³", bookmark:"ðŸ”–", note:"ðŸ“" };
    const hint = STATE.activeTags.length
      ? "No items match the selected tags."
      : "Tap + to add your first item";
    area.innerHTML = `<div class="empty">
      <div class="empty-ico">${icons[STATE.tab]||"ðŸ”"}</div>
      <div class="empty-title">Nothing here yet</div>
      <div class="empty-sub">${hint}</div>
    </div>`;
    return;
  }
}

function renderAll() { renderList(); renderSelectedTags(); }

function cardHTML(item) {
  const ico  = T_ICON[item.type]  || "ðŸ“„";
  const cls  = T_CLASS[item.type] || "ip";
  const sub  = item.username || item.url || (item.note||"").slice(0,55) || "";
  const tags = (item.tags||[]).slice(0,2).map(t => `<span class="bpill bt">#${esc(t)}</span>`).join("");
  const fav  = item.fav ? `<span class="bpill bf">â˜…</span>` : "";
  const pri  = item.priority === "high" ? `<span class="bpill bpp">âš¡</span>` : "";
  const exp  = STATE.expandedId === item.id;
  const id   = item.id;

  return `<div class="card${exp?" open":""}" id="card-${id}">
    <div class="card-top" onclick="toggleCard('${id}')">
      <div class="ci ${cls}">${ico}</div>
      <div class="cm">
        <div class="ct">${esc(item.title||"Untitled")}</div>
        <div class="cs">${esc(sub)}</div>
      </div>
      <div class="cbadges">${getFlagBadge(item)}${pri}${fav}${tags}</div>
      <div class="chev">âŒ„</div>
    </div>
    ${exp ? `
    <div class="card-detail">${detailHTML(item)}</div>
    <div class="card-actions">${actionsHTML(item)}</div>` : ""}
  </div>`;
}

function getFlagBadge(item) {
  const fd = item.flagDate;
  if (!fd) return "";
  const days = Math.ceil((new Date(fd).getTime() - Date.now()) / 86400000);
  let cls, ico, label;
  if (days < 0)        { cls="expired"; ico="â›”";  label=`${Math.abs(days)}d ago`; }
  else if (days === 0) { cls="urgent";  ico="âš ï¸"; label="Today"; }
  else if (days <= 3)  { cls="urgent";  ico="âš ï¸"; label=`${days}d left`; }
  else if (days <= 14) { cls="soon";    ico="ðŸ“…"; label=`${days}d left`; }
  else                 { cls="ok";      ico="ðŸ“…"; label=new Date(fd).toLocaleDateString("en-US",{month:"short",day:"numeric"}); }
  return `<span class="flag-badge ${cls}">${ico} ${label}</span>`;
}


function detailHTML(item) {
  const id = item.id;
  let h = "";

  if (item.username) h += dRow("USER", esc(item.username), `copyVal('${id}','username')`);

  if (item.password) {
    const vis = STATE.pwVisible[id];
    h += `<div class="dr">
      <span class="dl">PASS</span>
      <span class="dv${vis?"":" masked"}" id="dv-pw-${id}">${vis ? esc(item.password) : "â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢"}</span>
      <span class="da" onclick="togglePwVis('${id}')" id="eye-${id}">${vis?"ðŸ™ˆ":"ðŸ‘"}</span>
      <span class="da" onclick="copyVal('${id}','password')" title="Copy">âŽ˜</span>
    </div>`;
  }

  if (item.url)   h += dRow("URL",   `<span style="color:var(--blue)">${esc(item.url)}</span>`, `copyText('${esc(item.url)}')`);
  if (item.email) h += dRow("EMAIL", esc(item.email), `copyText('${esc(item.email)}')`);
  if (item.price) h += dRow("PRICE", esc(item.price));

  if (item.renewal) {
    const days = Math.ceil((new Date(item.renewal) - new Date()) / 86400000);
    const cls  = days < 0 ? "exp" : days < 30 ? "warn" : "ok";
    const ico  = days < 0 ? "âŒ"  : days < 30 ? "âš ï¸"   : "âœ…";
    const msg  = days < 0 ? `Expired ${Math.abs(days)}d ago` : days === 0 ? "Expires today" : `${days}d left`;
    h += `<div class="renewal ${cls}">${ico} Renews ${esc(item.renewal)} Â· ${msg}</div>`;
  }

  if (item.note) h += `<div class="note-block">${esc(item.note).replace(/\n/g,"<br>")}</div>`;

  if ((item.tags||[]).length) {
    h += `<div class="tag-chips">${item.tags.map(t=>`<span class="tc">#${esc(t)}</span>`).join("")}</div>`;
  }

  return `<div class="di">${h}</div>`;
}

function dRow(label, val, copyFn="") {
  return `<div class="dr">
    <span class="dl">${label}</span>
    <span class="dv">${val}</span>
    ${copyFn ? `<span class="da" onclick="${copyFn}" title="Copy">âŽ˜</span>` : ""}
  </div>`;
}

function actionsHTML(item) {
  const id = item.id;
  let b = "";
  if (item.type==="password" || item.type==="subscription") {
    b += cab("ðŸ‘¤","User","ca-copy", `copyVal('${id}','username')`);
    b += cab("ðŸ”‘","Pass","ca-copy", `copyVal('${id}','password')`);
  }
  if (item.url) b += cab("ðŸŒ","Open","ca-link", `openLink('${id}')`);
  b += cab(item.fav?"â˜…":"â˜†","Fav", "ca-fav",  `toggleFav('${id}')`);
  b += cab("âœï¸","Edit","ca-edit", `openEdit('${id}')`);
  b += cab("ðŸ—‘","Delete","ca-del", `askDelete('${id}')`);
  return b;
}

function cab(ico, label, cls, fn) {
  return `<button class="cab ${cls}" onclick="${fn}"><span class="ca-ico">${ico}</span>${label}</button>`;
}

function toggleCard(id) {
  STATE.expandedId = STATE.expandedId === id ? null : id;
  renderList();
  if (STATE.expandedId) {
    requestAnimationFrame(() => {
      $("card-"+id)?.scrollIntoView({ behavior:"smooth", block:"nearest" });
    });
  }
}

function togglePwVis(id) {
  STATE.pwVisible[id] = !STATE.pwVisible[id];
  renderList();
}

async function copyVal(id, field) {
  const item = STATE.items.find(i => i.id === id);
  if (!item) return;
  await copyText(item[field] || "");
  toast(`${field==="password"?"Password":"Username"} copied âœ“`);
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied âœ“"); }
  catch { toast("Copy not available"); }
}

function openLink(id) {
  const item = STATE.items.find(i => i.id === id);
  if (item?.url) window.open(item.url, "_blank", "noopener,noreferrer");
}

async function toggleFav(id) {
  const item = STATE.items.find(i => i.id === id);
  if (!item) return;
  item.fav = !item.fav;
  await saveItem(item);
  renderList();
  toast(item.fav ? "Added to favorites â˜…" : "Removed from favorites");
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  ADD / EDIT FORM
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function openAdd() {
  STATE.editId    = null;
  STATE.mTags     = [];
  STATE.mType     = "password";
  STATE.mPriority = "high";
  $("add-title").textContent = "Add Item";
  buildForm("password", null);
  openOverlay("add-overlay");
}

function openEdit(id) {
  const item = STATE.items.find(i => i.id === id);
  if (!item) return;
  STATE.editId    = id;
  STATE.mTags     = [...(item.tags||[])];
  STATE.mType     = item.type;
  STATE.mPriority = item.priority || "normal";
  $("add-title").textContent = "Edit Item";
  buildForm(item.type, item);
  openOverlay("add-overlay");
}

function buildForm(type, pre) {
  STATE.mType = type;
  const body = $("add-body");
  const foot = $("add-foot");

  const typeGrid = pre ? "" : `
    <div class="fg">
      <div class="fl">Type</div>
      <div class="type-grid">
        <div class="tcard${type==="password"?" on":""}" onclick="switchType('password',this)"><span class="tci">ðŸ”‘</span>Password</div>
        <div class="tcard${type==="subscription"?" on":""}" onclick="switchType('subscription',this)"><span class="tci">ðŸ’³</span>Subscription</div>
        <div class="tcard${type==="bookmark"?" on":""}" onclick="switchType('bookmark',this)"><span class="tci">ðŸ”–</span>Bookmark</div>
        <div class="tcard${type==="note"?" on":""}" onclick="switchType('note',this)"><span class="tci">ðŸ“</span>Note</div>
      </div>
    </div><div class="divider"></div>`;

  let fields = "";
  if (type === "password") {
    fields = `
      <div class="fg"><div class="fl">Title *</div><input class="fi" id="f-title" placeholder="Gmail, Netflixâ€¦" value="${esc(pre?.title||"")}" autocomplete="off"></div>
      <div class="fg"><div class="fl">Username / Email</div><input class="fi" id="f-username" placeholder="user@example.com" value="${esc(pre?.username||"")}" autocomplete="off"></div>
      <div class="fg"><div class="fl">Password</div>
        <div class="pw-wrap"><input class="fi mono" id="f-password" type="password" placeholder="â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢" value="${esc(pre?.password||"")}" autocomplete="new-password">
        <span class="pweye" onclick="tpw('f-password')">ðŸ‘</span></div>
        <div class="str-bar"><div class="str-fill" id="str-fill"></div></div>
      </div>
      <div class="fg"><div class="fl">Website URL</div><input class="fi" id="f-url" type="url" placeholder="https://" value="${esc(pre?.url||"")}"></div>
      <div class="fg"><div class="fl">Notes</div><textarea class="fi" id="f-note" placeholder="Optional notesâ€¦">${esc(pre?.note||"")}</textarea></div>`;
  } else if (type === "subscription") {
    fields = `
      <div class="fg"><div class="fl">Service Name *</div><input class="fi" id="f-title" placeholder="Netflix, Spotifyâ€¦" value="${esc(pre?.title||"")}"></div>
      <div class="fg"><div class="fl">Email / Username</div><input class="fi" id="f-username" placeholder="account email" value="${esc(pre?.username||"")}"></div>
      <div class="fg"><div class="fl">Password</div>
        <div class="pw-wrap"><input class="fi mono" id="f-password" type="password" placeholder="â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢" value="${esc(pre?.password||"")}" autocomplete="new-password">
        <span class="pweye" onclick="tpw('f-password')">ðŸ‘</span></div>
      </div>
      <div class="fg"><div class="fl">Price</div><input class="fi" id="f-price" placeholder="$9.99/month" value="${esc(pre?.price||"")}"></div>
      <div class="fg"><div class="fl">Renewal Date</div><input class="fi" id="f-renewal" type="date" value="${esc(pre?.renewal||"")}"></div>
      <div class="fg"><div class="fl">Website URL</div><input class="fi" id="f-url" placeholder="https://" value="${esc(pre?.url||"")}"></div>
      <div class="fg"><div class="fl">Notes</div><textarea class="fi" id="f-note">${esc(pre?.note||"")}</textarea></div>`;
  } else if (type === "bookmark") {
    fields = `
      <div class="fg"><div class="fl">Title *</div><input class="fi" id="f-title" placeholder="Bookmark name" value="${esc(pre?.title||"")}"></div>
      <div class="fg"><div class="fl">URL *</div><input class="fi" id="f-url" type="url" placeholder="https://" value="${esc(pre?.url||"")}"></div>
      <div class="fg"><div class="fl">Description</div><textarea class="fi" id="f-note" placeholder="What's this link about?">${esc(pre?.note||"")}</textarea></div>`;
  } else if (type === "note") {
    fields = `
      <div class="fg"><div class="fl">Title *</div><input class="fi" id="f-title" placeholder="Note title" value="${esc(pre?.title||"")}"></div>
      <div class="fg"><div class="fl">Content</div><textarea class="fi" id="f-note" style="min-height:140px" placeholder="Write your noteâ€¦">${esc(pre?.note||"")}</textarea></div>`;
  }

  const priorityBlock = `
    <div class="fg">
      <div class="fl">Priority</div>
      <div class="pri-row">
        <div class="pricard hi${STATE.mPriority==="high"?" on":""}" onclick="selectPri('high',this)"><span class="prico">âš¡</span>High</div>
        <div class="pricard${STATE.mPriority==="normal"?" on":""}" onclick="selectPri('normal',this)"><span class="prico">â—‹</span>Normal</div>
      </div>
    </div>`;

  const flagBlock = `
    <div class="fg">
      <div class="fl">Flag / Expires</div>
      <input class="fi" id="f-flagDate" type="date" value="${esc(pre?.flagDate||"")}" style="color-scheme:dark">
      <div style="font-size:11px;color:var(--faint);margin-top:3px">Optional â€” item will show an expiry countdown on cards</div>
    </div>`;

  const tagsBlock = `
    <div class="fg">
      <div class="fl">Tags</div>
      <div class="tag-add-row">
        <input class="fi" id="tag-inp" placeholder="Add a tagâ€¦" onkeydown="if(event.key==='Enter'){event.preventDefault();addTag()}">
        <button class="tadd-btn" onclick="addTag()">+ Add</button>
      </div>
      <div class="chips" id="mchips">${renderChips()}</div>
    </div>`;

  body.innerHTML = typeGrid + fields + priorityBlock + flagBlock + tagsBlock;
  foot.innerHTML = `
    <button class="btn ghost" onclick="closeOverlay('add-overlay')">Cancel</button>
    <button class="btn primary" onclick="submitItem()">${STATE.editId?"Save Changes":"Add Item"}</button>`;

  if (type === "password") {
    $("f-password")?.addEventListener("input", updateStrength);
    updateStrength();
  }
}

function selectPri(val, el) {
  STATE.mPriority = val;
  document.querySelectorAll(".pricard").forEach(c => c.classList.remove("on"));
  el.classList.add("on");
}

function switchType(type, el) {
  STATE.mType = type;
  document.querySelectorAll(".tcard").forEach(c => c.classList.remove("on"));
  el.classList.add("on");
  buildForm(type, null);
}

function tpw(id) {
  const el = $(id);
  el.type  = el.type === "password" ? "text" : "password";
}

function updateStrength() {
  const pw = $("f-password")?.value || "";
  let s = 0;
  if (pw.length >= 8)  s++;
  if (pw.length >= 14) s++;
  if (/[A-Z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  const colors = ["","#f87171","#fbbf24","#fbbf24","#4ade80","#4ade80"];
  const fill   = $("str-fill");
  if (fill) { fill.style.width = (s * 20) + "%"; fill.style.background = colors[s]||""; }
}

function addTag() {
  const inp = $("tag-inp");
  const val = inp.value.trim().toLowerCase().replace(/\s+/g,"-");
  if (!val || STATE.mTags.includes(val)) { inp.value = ""; return; }
  STATE.mTags.push(val);
  inp.value = "";
  refreshChips();
}
function removeTag(t) { STATE.mTags = STATE.mTags.filter(v => v !== t); refreshChips(); }
function renderChips() {
  return STATE.mTags.map(t =>
    `<div class="chip">#${esc(t)}<span class="chip-x" onclick="removeTag('${esc(t)}')">âœ•</span></div>`
  ).join("");
}
function refreshChips() { const el = $("mchips"); if (el) el.innerHTML = renderChips(); }

function fv(id) { return ($(id)?.value || "").trim(); }

async function submitItem() {
  const title = fv("f-title");
  if (!title) { toast("Title is required"); return; }
  const existing = STATE.editId ? STATE.items.find(i => i.id === STATE.editId) : null;
  const item = {
    id       : STATE.editId || genId(),
    type     : existing?.type || STATE.mType,
    fav      : existing?.fav  || false,
    created  : existing?.created || Date.now(),
    title,
    username : fv("f-username"),
    password : fv("f-password"),
    url      : fv("f-url"),
    email    : fv("f-email"),
    note     : fv("f-note"),
    price    : fv("f-price"),
    renewal  : fv("f-renewal"),
    tags     : [...STATE.mTags],
    priority : STATE.mPriority || "normal",
    flagDate : fv("f-flagDate") || null,
  };
  await saveItem(item);
  closeOverlay("add-overlay");
  renderAll(); updateStats();
  toast(STATE.editId ? "Item updated âœ“" : "Item added âœ“");
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  DELETE
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function askDelete(id) {
  const item = STATE.items.find(i => i.id === id);
  if (!item) return;
  $("confirm-title").textContent  = "Delete Item";
  $("confirm-msg").textContent    = `Delete "${item.title}"? This cannot be undone.`;
  $("confirm-ok").textContent     = "Delete";
  $("confirm-ok").onclick = async () => {
    await removeItem(id);
    closeOverlay("confirm-overlay");
    toast("Deleted");
  };
  openOverlay("confirm-overlay");
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  IMPORT / EXPORT
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
async function exportJSON() {
  const encrypted = await Crypto.encrypt(STATE.items, STATE.masterKey);
  const payload   = JSON.stringify({ version:2, app:"vault-pwa", exported:new Date().toISOString(), vault:encrypted });
  dl("vault-backup.enc.json", payload, "application/json");
  toast("Vault exported âœ“");
}

function exportCSV() {
  const rows = [["ID","Type","Title","Username","URL","Email","Price","Renewal","Tags","Note"]];
  STATE.items.forEach(i => rows.push([
    i.id, i.type, i.title||"", i.username||"", i.url||"",
    i.email||"", i.price||"", i.renewal||"", (i.tags||[]).join(";"), i.note||"",
  ]));
  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(",")).join("\n");
  dl("vault-export.csv", csv, "text/csv");
  toast("CSV exported (passwords excluded for safety)");
}

function dl(name, content, mime) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([content], { type:mime }));
  a.download = name; a.click();
}

function pickImport() { $("imp-file").click(); }

async function doImport(e) {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const text    = await file.text();
    const payload = JSON.parse(text);
    if (!payload.vault) throw new Error("Invalid format");
    const imported = await Crypto.decrypt(payload.vault, STATE.masterKey);
    let added = 0;
    for (const item of imported) {
      if (!STATE.items.find(i => i.id === item.id)) { STATE.items.push(item); added++; }
    }
    await persistItems();
    if (STATE.drive.token) triggerSync();
    renderAll(); updateStats();
    toast(`Imported ${added} items âœ“`);
  } catch (err) { toast("Import failed: " + err.message); }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  SETTINGS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function updateStats() {
  const grid = $("stat-grid");
  if (!grid) return;
  const c = { password:0, subscription:0, bookmark:0, note:0 };
  STATE.items.forEach(i => { if (c[i.type] !== undefined) c[i.type]++; });
  const favCount = STATE.items.filter(i => i.fav).length;
  grid.innerHTML = [
    [STATE.items.length, "Total Items", "ðŸ—„ï¸"],
    [favCount,           "Favorites",   "â˜…"],
    [c.password,         "Passwords",   "ðŸ”‘"],
    [c.subscription,     "Subscriptions","ðŸ’³"],
    [c.bookmark,         "Bookmarks",   "ðŸ”–"],
    [c.note,             "Notes",       "ðŸ“"],
  ].map(([n,l,i]) => `<div class="stat-box"><div class="stat-n">${n}</div><div class="stat-l">${i} ${l}</div></div>`).join("");
}

async function changeMasterPw() {
  const nw = $("new-pw").value.trim();
  if (nw.length < 4) { toast("Min 4 characters"); return; }
  STATE.masterKey = nw;
  await persistItems();
  LS.set("vault_hash", await Crypto.hashPassword(nw));
  $("new-pw").value = "";
  if (STATE.drive.token) triggerSync();
  toast("Master password updated âœ“");
}

function clearAll() {
  $("confirm-title").textContent = "Wipe All Data";
  $("confirm-msg").textContent   = "This permanently deletes your ENTIRE vault â€” all passwords, bookmarks, and notes. This CANNOT be undone.";
  $("confirm-ok").textContent    = "Wipe Everything";
  $("confirm-ok").onclick = () => {
    localStorage.clear();
    STATE.items = []; STATE.masterKey = null;
    closeOverlay("confirm-overlay");
    lockVault();
    toast("All data wiped");
  };
  openOverlay("confirm-overlay");
}

function setSort(val, el) {
  STATE.sort = val;
  document.querySelectorAll(".sort-chip").forEach(c => c.classList.remove("on"));
  el.classList.add("on");
  renderList();
  toast("Sort updated");
}

// â”€â”€ Password generator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function genPassword() {
  let ch = "";
  if (STATE.genOpts.upper) ch += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (STATE.genOpts.lower) ch += "abcdefghijklmnopqrstuvwxyz";
  if (STATE.genOpts.num)   ch += "0123456789";
  if (STATE.genOpts.sym)   ch += "!@#$%^&*()-_=+[]{}|;:,.<>?";
  if (!ch) ch = "abcdefghijklmnopqrstuvwxyz";
  const len = +$("gen-len").value;
  let pw = "";
  for (let i = 0; i < len; i++) pw += ch[Math.floor(Math.random() * ch.length)];
  $("gen-out").textContent = pw;
}
function copyGenPw() {
  const pw = $("gen-out").textContent;
  if (pw === "Tap Generate") { toast("Generate first"); return; }
  navigator.clipboard.writeText(pw).then(() => toast("Password copied âœ“"));
}
function genToggle(k, el) {
  STATE.genOpts[k] = !STATE.genOpts[k];
  el.classList.toggle("on", STATE.genOpts[k]);
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  PAGE NAV
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function showPage(p) {
  const home = p === "home";
  ["statusbar","tabs","search-row","list"].forEach(id => {
    const el = $(id); if (el) el.style.display = id==="list" ? (home?"flex":"none") : (home?"":"none");
  });
  const tfr = $("tag-filter-row");
  if (tfr) tfr.style.display = home ? "flex" : "none";
  $("drive-banner").style.display = (home && !STATE.drive.token && !LS.get("drive_banner_dismissed")) ? "flex" : "none";
  $("settings").classList.toggle("show", !home);
  $("fab").style.display = home ? "flex" : "none";
  $("nav-home").classList.toggle("on", home);
  $("nav-set").classList.toggle("on", !home);
  if (!home) { updateStats(); renderDrivePanel(); }
}

function dismissBanner() {
  $("drive-banner").classList.remove("show");
  LS.set("drive_banner_dismissed","1");
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  OVERLAYS
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function openOverlay(id)  { $(id).classList.add("open"); }
function closeOverlay(id) { $(id).classList.remove("open"); }
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".overlay").forEach(o => {
    o.addEventListener("click", e => { if (e.target === o) o.classList.remove("open"); });
  });
});

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  TOAST
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
let _tt;
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(_tt);
  _tt = setTimeout(() => t.classList.remove("show"), 2600);
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  TAG AUTOCOMPLETE (inline)
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
function onTagSearch(inp) {
  const q = inp.value.trim();
  $("tag-q-clear").style.display = q ? "block" : "none";
  renderTagAutocomplete(q);
}

function renderTagAutocomplete(q) {
  const dropdown = $("tag-autocomplete");
  if (!dropdown) return;
  if (!q) { dropdown.style.display = "none"; return; }
  const ql = q.toLowerCase();
  const matches = getAllTags()
    .filter(t => t.toLowerCase().includes(ql) && !STATE.activeTags.includes(t))
    .slice(0, 20);
  if (!matches.length) { dropdown.style.display = "none"; return; }
  dropdown.style.display = "flex";
  dropdown.innerHTML = matches.map(t => {
    const n = STATE.items.filter(i => (i.tags||[]).includes(t)).length;
    return `<span class="tag-ac-chip" onclick="selectAutoTag('${esc(t)}')">#${esc(t)} <span class="tag-ac-count">${n}</span></span>`;
  }).join("");
}

function selectAutoTag(tag) {
  if (!STATE.activeTags.includes(tag)) {
    STATE.activeTags.push(tag);
    renderSelectedTags();
    renderList();
  }
  const inp = $("tag-q");
  if (inp) inp.value = "";
  $("tag-q-clear").style.display = "none";
  $("tag-autocomplete").style.display = "none";
}

function removeActiveTag(tag) {
  STATE.activeTags = STATE.activeTags.filter(t => t !== tag);
  renderSelectedTags();
  renderList();
}

function clearAllTags() {
  STATE.activeTags = [];
  renderSelectedTags();
  renderList();
}

function renderSelectedTags() {
  const el = $("selected-tags");
  if (!el) return;
  const n = STATE.activeTags.length;
  el.style.display = n ? "flex" : "none";
  el.innerHTML = STATE.activeTags.map(t =>
    `<span class="stag">#${esc(t)}<span class="stag-x" onclick="removeActiveTag('${esc(t)}')">âœ•</span></span>`
  ).join("") + (n > 1 ? `<span class="stag-clear" onclick="clearAllTags()">Clear all</span>` : "");
}

function clearTagSearch() {
  const inp = $("tag-q");
  if (inp) inp.value = "";
  $("tag-q-clear").style.display = "none";
  $("tag-autocomplete").style.display = "none";
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  START
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
boot();
