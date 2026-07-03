/* ═══════════════════════════════════════════════════════════
   VAULT — app.js
   AES-256-GCM encryption · PBKDF2 key derivation
   Google Drive OAuth2 sync · Full offline PWA
   ═══════════════════════════════════════════════════════════ */

"use strict";

// ── Silent OAuth iframe handler ───────────────────────────
// If we're inside a hidden iframe for silent token refresh,
// extract the token and send it back to the parent — don't boot the app.
if (window !== window.parent && location.hash.includes("access_token")) {
  try {
    const params = new URLSearchParams(location.hash.slice(1));
    const token = params.get("access_token");
    const expiresIn = parseInt(params.get("expires_in") || "3600", 10);
    window.parent.postMessage({
      type: "vault-silent-auth",
      token: token,
      expiresIn: expiresIn,
    }, location.origin);
  } catch (e) {
    window.parent.postMessage({ type: "vault-silent-auth", token: null }, location.origin);
  }
  // Stop — don't initialize the full app in the iframe
  throw new Error("SILENT_AUTH_IFRAME_HALT");
}

// ── Shortcuts ─────────────────────────────────────────────
const $ = id => document.getElementById(id);
const enc = s  => new TextEncoder().encode(s);
const dec = b  => new TextDecoder().decode(b);
const rnd = n  => crypto.getRandomValues(new Uint8Array(n));
const b64e = u => btoa(String.fromCharCode(...u));
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

// ── SVG Icons for Card Actions ─────────────────────────────
const SVGS = {
  user: `<svg class="cab-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
  key: `<svg class="cab-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>`,
  link: `<svg class="cab-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>`,
  starFilled: `<svg class="cab-svg" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
  starEmpty: `<svg class="cab-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
  edit: `<svg class="cab-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 1 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`,
  trash: `<svg class="cab-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>`
};
const esc  = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
const sleep = ms => new Promise(r => setTimeout(r, ms));
const vibrate = ms => { try { navigator?.vibrate?.(ms); } catch {} };

// ── LS wrapper ────────────────────────────────────────────
const LS = {
  get : k  => { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
  set : (k,v) => localStorage.setItem(k, JSON.stringify(v)),
  del : k  => localStorage.removeItem(k),
};

// ── IDB wrapper (IndexedDB) ───────────────────────────────
const IDB = {
  dbName: "vault_db",
  storeName: "store",
  
  _getDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore(this.storeName);
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  },
  
  async get(key) {
    try {
      const db = await this._getDB();
      return new Promise((resolve, reject) => {
        const transaction = db.transaction(this.storeName, "readonly");
        const store = transaction.objectStore(this.storeName);
        const request = store.get(key);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
    } catch {
      return null;
    }
  },
  
  async set(key, val) {
    const db = await this._getDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(this.storeName, "readwrite");
      const store = transaction.objectStore(this.storeName);
      const request = store.put(val, key);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  },
  
  async del(key) {
    const db = await this._getDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(this.storeName, "readwrite");
      const store = transaction.objectStore(this.storeName);
      const request = store.put(undefined, key); // or delete
      const requestDel = store.delete(key);
      requestDel.onsuccess = () => resolve(requestDel.result);
      requestDel.onerror = () => reject(requestDel.error);
    });
  }
};

// ══════════════════════════════════════════════════════════
//  CRYPTO  (AES-256-GCM + PBKDF2)
// ══════════════════════════════════════════════════════════
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

  async verifyPassword(password, hash) {
    const h = await this.hashPassword(password);
    return h === hash;
  },
};

// ══════════════════════════════════════════════════════════
//  STATE
// ══════════════════════════════════════════════════════════
let STATE = {
  masterKey        : null,
  items            : [],
  tab              : "dash",
  typeFilter       : null,
  favOnly          : false,
  activeTags       : [],
  tagMatchStrategy : "and",       // and | or
  focusedSuggestionIndex: -1,
  focusedActiveTagIndex: -1,
  focusedSearchButtonIndex: -1,
  suggestions      : [],
  deepSearch       : false,
  autoSuggest      : false,
  sort             : "urgency",   // urgency | name | name-d | new | old | type
  expandedId       : null,
  pwVisible        : {},
  editId           : null,
  focusedFormTagIndex: -1,
  focusedMTagIndex : -1,
  mTags            : [],
  mType            : "password",
  mPriority        : "high",
  mSubitems        : [],
  mColor           : "purple",
  mDashboard       : false,
  currentFilteredList: [],
  renderLimit      : 50,
  autoLockMin      : 5,
  autofillExtensionId: "",
  theme            : "system",
  drive: {
    token       : null,
    tokenExpiry : null,
    fileId      : null,
    status      : "offline",
    lastSync    : null,
  }
};

// ══════════════════════════════════════════════════════════
//  STORAGE  — only encrypted blobs ever hit localStorage
// ══════════════════════════════════════════════════════════
async function persistItems() {
  if (!STATE.masterKey) return;
  if (!STATE.items.length) { await IDB.del("vault_data"); return; }
  const blob = await Crypto.encrypt(STATE.items, STATE.masterKey);
  await IDB.set("vault_data", blob);
  syncWithExtension(false);
}

async function loadItems() {
  const blob = await IDB.get("vault_data");
  if (!blob) { STATE.items = []; return; }
  try {
    STATE.items = await Crypto.decrypt(blob, STATE.masterKey);
    validateItems();
    syncWithExtension(false);
  } catch {
    STATE.items = [];
  }
}

// ── Data integrity validation ──────────────────────────
function validateItems() {
  STATE.items = STATE.items.filter(item => {
    if (!item || typeof item !== 'object') return false;
    if (!item.id) item.id = genId();
    if (!item.type) item.type = 'note';
    if (!item.title) item.title = 'Untitled';
    if (!item.created) item.created = Date.now();
    if (!Array.isArray(item.tags)) item.tags = [];
    if (typeof item.fav !== 'boolean') item.fav = false;
    if (item.type === 'todo' && !Array.isArray(item.subitems)) item.subitems = [];
    return true;
  });
}

// ══════════════════════════════════════════════════════════
//  BOOT
// ══════════════════════════════════════════════════════════
async function boot() {
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  }
  handleOAuthCallback();
  STATE.drive.token       = LS.get("drive_token");
  STATE.drive.tokenExpiry = LS.get("drive_token_expiry");
  STATE.drive.fileId      = LS.get("drive_file_id");
  STATE.drive.lastSync    = LS.get("drive_last_sync");
  STATE.autoLockMin    = LS.get("vault_autolock") ?? 5;
  STATE.autofillExtensionId = LS.get("vault_autofill_extension_id") || "";
  STATE.theme = LS.get("vault_theme") || "system";
  applyTheme(STATE.theme);
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
      if (STATE.theme === 'system') applyTheme('system');
    });
  }
  const configured = VAULT_CONFIG.GOOGLE_CLIENT_ID &&
    !VAULT_CONFIG.GOOGLE_CLIENT_ID.startsWith("PASTE_");

  const isConnected = LS.get("drive_connected") === "true";
  const expired = isTokenExpired();
  if (configured) {
    if (isConnected) {
      if (!navigator.onLine) {
        STATE.drive.status = "offline";
      } else {
        STATE.drive.status = (STATE.drive.token && !expired) ? "synced" : "error";
      }
    } else {
      STATE.drive.status = "offline";
    }
  } else {
    STATE.drive.status = "noconfig";
  }
  const hasVault = !!LS.get("vault_hash");
  // Auto-unlock if session key exists and within inactivity window (page refresh)
  const sessionPin = LS.get("vault_session_key");
  const lastActivity = parseInt(LS.get("vault_last_activity") || "0", 10);
  const autolockMins = STATE.autoLockMin ?? 5;
  const elapsedMins = lastActivity > 0 ? (Date.now() - lastActivity) / 60000 : Infinity;
  const sessionValid = autolockMins === 0 || elapsedMins < autolockMins;

  if (hasVault && sessionPin && sessionValid) {
    try {
      const ok = await Crypto.verifyPassword(sessionPin, LS.get("vault_hash"));
      if (ok) {
        STATE.masterKey = sessionPin;
        LS.set("vault_last_activity", Date.now().toString());
        await loadItems();
        renderSyncBadge();
        openApp();
        return;
      }
    } catch(e) {}
    LS.del("vault_session_key");
    LS.del("vault_last_activity");
  } else {
    LS.del("vault_session_key");
    LS.del("vault_last_activity");
  }
  if (!hasVault) {
    $("pin-label").textContent = "Create a PIN";
    $("lock-hint").textContent = "Choose a numeric PIN (min 4 digits)";
  } else {
    // Show biometric button if registered
    if (LS.get("vault_bio_cred") && await isBioAvailable()) {
      $("bio-section").classList.add("show");
    }
    // Show forgot PIN link if secret question is configured
    if (LS.get("vault_sq_question")) {
      $("forgot-link").style.display = "";
    }
  }
  renderPinDots();
  renderSyncBadge();
  checkLockout();
  // Restore auto-lock setting UI
  initAutoLockUI();
  initAutofillUI();
  autoBiometricUnlock();
}

// ══════════════════════════════════════════════════════════
//  PIN PAD / LOCK / UNLOCK
// ══════════════════════════════════════════════════════════
let _pin = "";
let _pinConfirm = null;
let _lockoutTimer = null;

function numpadPress(digit) {
  if (_pin.length >= 12) return;
  vibrate(25);
  _pin += digit;
  renderPinDots();
  const btn = $("nk-submit");
  if (btn) btn.classList.toggle("dim", _pin.length < 4);
}

function numpadBack() {
  if (!_pin.length) return;
  vibrate(15);
  _pin = "";
  renderPinDots();
  const btn = $("nk-submit");
  if (btn) btn.classList.add("dim");
}

function renderPinDots() {
  const el = $("pin-dots");
  if (!el) return;
  const len = _pin.length;
  let html = "";
  if (len < 4) {
    for (let i = 0; i < 4; i++) html += `<div class="pin-dot${i < len ? " filled" : ""}${i === len ? " cursor" : ""}"></div>`;
  } else {
    for (let i = 0; i < len; i++) html += `<div class="pin-dot filled"></div>`;
    if (len < 12) html += `<div class="pin-dot cursor"></div>`;
  }
  el.innerHTML = html;
}

async function handlePinSubmit() {
  if (_pin.length < 4) return;
  // PIN reset mode (after SQ verification)
  if (_pinResetMode) { await handlePinReset(); return; }
  setLockErr("");
  const hasVault = !!LS.get("vault_hash");
  if (!hasVault) {
    if (_pinConfirm === null) {
      _pinConfirm = _pin; _pin = "";
      $("pin-label").textContent = "Confirm your PIN";
      $("lock-hint").textContent = "Re-enter the same PIN to confirm";
      renderPinDots(); $("nk-submit").classList.add("dim"); return;
    }
    if (_pin !== _pinConfirm) {
      setLockErr("PINs don't match"); shakeDots();
      _pin = ""; _pinConfirm = null;
      $("pin-label").textContent = "Create a PIN";
      $("lock-hint").textContent = "Choose a numeric PIN (min 4 digits)";
      renderPinDots(); $("nk-submit").classList.add("dim"); return;
    }
    await setupVault(_pin); return;
  }
  const hash = await Crypto.hashPassword(_pin);
  if (hash !== LS.get("vault_hash")) {
    recordFailedAttempt();
    const remaining = 3 - getFailCount();
    if (remaining <= 0) { startLockout(); }
    else { setLockErr("Wrong PIN — " + remaining + " attempt" + (remaining===1?"":"s") + " left"); shakeDots(); }
    _pin = ""; renderPinDots(); $("nk-submit").classList.add("dim"); return;
  }
  clearFailCount(); STATE.masterKey = _pin;
  LS.set("vault_session_key", _pin);
  LS.set("vault_last_activity", Date.now().toString());
  _pin = "";
  await loadItems(); openApp();
}

async function setupVault(pw) {
  if (pw.length < 4) { setLockErr("Min 4 digits"); return; }
  const hash = await Crypto.hashPassword(pw);
  LS.set("vault_hash", hash);
  STATE.masterKey = pw; STATE.items = []; _pin = ""; _pinConfirm = null;
  LS.set("vault_session_key", pw);
  LS.set("vault_last_activity", Date.now().toString());
  $("pin-entry").style.display = "none";
  $("lock-hint").style.display = "none";
  $("bio-section").classList.remove("show");
  $("forgot-link").style.display = "none";
  const lh = $("lock-header"); if (lh) lh.style.display = "none";
  // Hide the glassmorphism card so it doesn't show empty
  const lc = document.querySelector('.lock-card'); if (lc) lc.style.display = 'none';
  $("sq-setup").style.display = "flex";
  // Reset bio-asked flag so new vault users get the prompt
  LS.del("vault_bio_asked");
}

function openApp() {
  $("lock").classList.add("gone");
  renderAll(); renderDashboard(); showPage("home"); updateStats(); renderDrivePanel();
  const configured = VAULT_CONFIG.GOOGLE_CLIENT_ID && !VAULT_CONFIG.GOOGLE_CLIENT_ID.startsWith("PASTE_");
  // Check if user just returned from OAuth (fresh connect)
  if (STATE.drive.token && !STATE.drive.lastSync) {
    // Just connected — show toast and pull first to prevent overwriting cloud backup
    setTimeout(() => {
      toast("Google Drive connected", "success");
      renderSyncBadge();
      pullFromDrive().then(success => {
        if (success) triggerSync();
      });
    }, 400);
  } else if (STATE.drive.token) {
    setTimeout(() => pullFromDrive(), 400);
  } else if (LS.get("drive_connected") === "true") {
    if (!navigator.onLine) {
      setSyncStatus("offline");
    } else {
      // Drive is connected, but token is missing or expired.
      // Try to silently refresh the token.
      setTimeout(() => {
        console.log("[Vault] Re-checking Google Drive connection...");
        setSyncStatus("syncing");
        silentTokenRefresh().then(refreshed => {
          if (refreshed) {
            pullFromDrive();
          } else {
            setSyncStatus("error");
            toast("Drive session expired — click sync badge to reconnect", "warn");
          }
        });
      }, 400);
    }
  } else if (!STATE.drive.token && !LS.get("drive_banner_dismissed")) {
    $("drive-banner").classList.add("show");
    $("db-msg").textContent = configured
      ? "Connect Google Drive to sync your vault across devices"
      : "⚙️ Add your Google Client ID in config.js to enable Drive sync";
  }

  if (!window._visibilitySyncListener) {
    window._visibilitySyncListener = () => {
      if (document.visibilityState === "visible" && STATE.drive.token && STATE.masterKey && navigator.onLine) {
        const now = Date.now();
        const lastSync = window._lastAutoSyncTime || 0;
        if (now - lastSync > 600000) { // 10 minutes cooldown
          window._lastAutoSyncTime = now;
          pullFromDrive();
        }
      }
    };
    document.addEventListener("visibilitychange", window._visibilitySyncListener);
  }

  if (!window._onlineSyncListener) {
    window._onlineSyncListener = () => {
      if (STATE.drive.token && STATE.masterKey) {
        pullFromDrive().then(success => {
          if (success) triggerSync();
        });
      } else if (LS.get("drive_connected") === "true" && STATE.masterKey) {
        console.log("[Vault] Network restored, re-checking Google Drive connection...");
        setSyncStatus("syncing");
        silentTokenRefresh().then(refreshed => {
          if (refreshed) {
            pullFromDrive();
          } else {
            setSyncStatus("error");
          }
        });
      }
    };
    window.addEventListener("online", window._onlineSyncListener);
  }
  const listEl = $("list");
  if (listEl && !window._listScrollListener) {
    window._listScrollListener = () => {
      if (listEl.scrollTop + listEl.clientHeight >= listEl.scrollHeight - 300) {
        if (STATE.renderLimit < STATE.currentFilteredList.length) {
          STATE.renderLimit += 50;
          renderMoreListItems();
        }
      }
    };
    listEl.addEventListener("scroll", window._listScrollListener);
  }
  // Offer biometric registration if not already set up
  offerBioRegistration();
  // Start auto-lock timer
  startAutoLock();
  // FAB pulse hint if empty
  updateFabPulse();
}

function lockVault() {
  toggleSettings(false);
  STATE.masterKey = null; STATE.items = []; STATE.expandedId = null; STATE.pwVisible = {};
  _pin = ""; _pinConfirm = null;
  LS.del("vault_session_key");
  LS.del("vault_last_activity");
  stopAutoLock();
  syncWithExtension(true);
  
  // Clear search and suggestions state
  const suggestEl = $("search-suggestions");
  if (suggestEl) suggestEl.style.display = "none";
  const qEl = $("q");
  if (qEl) qEl.value = "";
  const qClearEl = $("q-clear");
  if (qClearEl) qClearEl.style.display = "none";
  STATE.focusedSuggestionIndex = -1;
  STATE.focusedSearchButtonIndex = -1;
  STATE.focusedActiveTagIndex = -1;
  STATE.activeTags = [];
  STATE.typeFilter = null;
  updateSearchButtonsHighlight();

  const lh = $("lock-header"); if (lh) lh.style.display = "";
  $("lock").classList.remove("gone"); setLockErr(""); renderPinDots();
  const btn = $("nk-submit"); if (btn) btn.classList.add("dim");
  const hasVault = !!LS.get("vault_hash");
  $("pin-label").textContent = hasVault ? "Enter PIN" : "Create a PIN";
  $("lock-hint").textContent = hasVault ? "Min 4 digits · Locked after 3 wrong attempts" : "Choose a numeric PIN (min 4 digits)";
  // Show biometric if registered
  if (hasVault && LS.get("vault_bio_cred")) {
    $("bio-section").classList.add("show");
  } else {
    $("bio-section").classList.remove("show");
  }
  // Show forgot link if SQ configured
  $("forgot-link").style.display = (hasVault && LS.get("vault_sq_question")) ? "" : "none";
  // Hide SQ panels
  $("sq-recovery").style.display = "none";
  $("sq-setup").style.display = "none";
  $("pin-entry").style.display = "flex";
  $("lock-hint").style.display = "";
  // Ensure lock-card is visible
  const lc = document.querySelector('.lock-card'); if (lc) lc.style.display = '';
  autoBiometricUnlock();
}

function setLockErr(msg) { $("lock-err").textContent = msg; }
function shakeDots() { const el=$("pin-dots"); if(!el) return; el.classList.add("shake"); setTimeout(()=>el.classList.remove("shake"),500); }

function getFailCount() { return LS.get("vault_fails") || 0; }
function recordFailedAttempt() { LS.set("vault_fails", getFailCount() + 1); }
function clearFailCount() { LS.del("vault_fails"); LS.del("vault_lockout_until"); }
function startLockout() {
  const until = Date.now() + 10*60*1000;
  LS.set("vault_lockout_until", until); LS.set("vault_fails", 0); applyLockout(until);
}
function checkLockout() {
  const until = LS.get("vault_lockout_until");
  if (!until || Date.now() >= until) { endLockout(); return; }
  applyLockout(until);
}
function applyLockout(until) {
  $("pin-entry").style.display = "none"; $("lock-hint").style.display = "none";
  $("forgot-link").style.display = "none";
  $("sq-recovery").style.display = "none";
  $("bio-section").classList.remove("show");
  const lh = $("lock-header"); if (lh) lh.style.display = "none";
  // Hide lock-card during lockout
  const lc = document.querySelector('.lock-card'); if (lc) lc.style.display = 'none';
  $("lock-blocked").classList.add("show"); setLockErr("");
  // Show SQ bypass if configured
  const sqQ = LS.get("vault_sq_question");
  const lbSQ = $("lb-sq-section");
  if (sqQ && lbSQ) {
    $("lb-sq-q").textContent = sqQ;
    lbSQ.style.display = "";
  } else if (lbSQ) {
    lbSQ.style.display = "none";
  }
  if (_lockoutTimer) clearInterval(_lockoutTimer);
  _lockoutTimer = setInterval(() => {
    const rem = until - Date.now();
    if (rem <= 0) { endLockout(); return; }
    const m = Math.floor(rem/60000), s = Math.floor((rem%60000)/1000);
    $("lb-timer").textContent = String(m).padStart(2,"0")+":"+String(s).padStart(2,"0");
  }, 250);
}
function endLockout() {
  if (_lockoutTimer) { clearInterval(_lockoutTimer); _lockoutTimer = null; }
  LS.del("vault_lockout_until");
  $("lock-blocked").classList.remove("show");
  // Clear SQ inputs
  const lbAns = $("lb-sq-ans"); if (lbAns) lbAns.value = "";
  const lh = $("lock-header"); if (lh) lh.style.display = "";
  // Re-show lock-card and PIN entry
  const lc = document.querySelector('.lock-card'); if (lc) lc.style.display = '';
  $("pin-entry").style.display = "flex"; $("lock-hint").style.display = "";
  _pin = ""; renderPinDots(); $("nk-submit").classList.add("dim");
  // Re-show forgot link and biometric if available
  if (LS.get("vault_sq_question")) $("forgot-link").style.display = "";
  if (LS.get("vault_bio_cred")) $("bio-section").classList.add("show");
  autoBiometricUnlock();
}

// ══════════════════════════════════════════════════════════
//  SECRET QUESTION SYSTEM
// ══════════════════════════════════════════════════════════
async function hashSQAnswer(answer) {
  const buf = await crypto.subtle.digest("SHA-256", enc(answer.toLowerCase().trim() + "__vault_sq_salt__"));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("");
}

function onSQPresetChange() {
  const sel = $("sq-setup-preset");
  $("sq-custom-wrap").style.display = sel.value === "__custom__" ? "" : "none";
}

async function saveSQFromSetup() {
  const sel = $("sq-setup-preset");
  let question = sel.value === "__custom__" ? $("sq-setup-custom").value.trim() : sel.value;
  const answer = $("sq-setup-answer").value.trim();
  if (!question || !answer) { toast("Please fill in question and answer"); return; }
  const hash = await hashSQAnswer(answer);
  LS.set("vault_sq_question", question);
  LS.set("vault_sq_hash", hash);
  $("sq-setup").style.display = "none";
  openApp();
  toast("Recovery question saved", "success");
}

function skipSQSetup() {
  $("sq-setup").style.display = "none";
  openApp();
}

function showForgotPIN() {
  const question = LS.get("vault_sq_question");
  if (!question) { toast("No secret question set"); return; }
  $("pin-entry").style.display = "none";
  $("lock-hint").style.display = "none";
  $("forgot-link").style.display = "none";
  $("bio-section").classList.remove("show");
  const lh = $("lock-header"); if (lh) lh.style.display = "none";
  // Hide the glassmorphism card during recovery
  const lc = document.querySelector('.lock-card'); if (lc) lc.style.display = 'none';
  $("sq-rec-q").textContent = question;
  $("sq-rec-ans").value = "";
  $("sq-rec-err").textContent = "";
  $("sq-recovery").style.display = "flex";
  $("sq-rec-ans").focus();
}

function backToPin() {
  $("sq-recovery").style.display = "none";
  const lh = $("lock-header"); if (lh) lh.style.display = "";
  // Re-show lock-card
  const lc = document.querySelector('.lock-card'); if (lc) lc.style.display = '';
  $("pin-entry").style.display = "flex";
  $("lock-hint").style.display = "";
  $("forgot-link").style.display = "";
  if (LS.get("vault_bio_cred")) $("bio-section").classList.add("show");
  _pin = ""; renderPinDots();
  autoBiometricUnlock();
}

let _pinResetMode = false;
let _pinResetConfirm = null;

async function verifySQAnswer() {
  const answer = $("sq-rec-ans").value.trim();
  if (!answer) return;
  const hash = await hashSQAnswer(answer);
  if (hash !== LS.get("vault_sq_hash")) {
    $("sq-rec-err").textContent = "Wrong answer";
    $("sq-rec-ans").value = "";
    $("sq-rec-ans").classList.add("shake");
    setTimeout(() => $("sq-rec-ans").classList.remove("shake"), 500);
    return;
  }
  // Correct — start PIN reset
  $("sq-recovery").style.display = "none";
  startPinReset();
}

function startPinReset() {
  _pinResetMode = true;
  _pinResetConfirm = null;
  _pin = "";
  clearFailCount();
  // Re-show lock-card for PIN entry
  const lc = document.querySelector('.lock-card'); if (lc) lc.style.display = '';
  $("pin-entry").style.display = "flex";
  $("lock-hint").style.display = "";
  $("forgot-link").style.display = "none";
  $("pin-label").textContent = "Create your new PIN";
  $("lock-hint").textContent = "Choose a new numeric PIN (min 4 digits)";
  setLockErr("");
  renderPinDots();
  $("nk-submit").classList.add("dim");
}

async function handlePinReset() {
  if (_pin.length < 4) return;
  if (_pinResetConfirm === null) {
    _pinResetConfirm = _pin; _pin = "";
    $("pin-label").textContent = "Confirm new PIN";
    $("lock-hint").textContent = "Re-enter the same PIN to confirm";
    renderPinDots(); $("nk-submit").classList.add("dim"); return;
  }
  if (_pin !== _pinResetConfirm) {
    setLockErr("PINs don't match"); shakeDots();
    _pin = ""; _pinResetConfirm = null;
    $("pin-label").textContent = "Create your new PIN";
    $("lock-hint").textContent = "Choose a new numeric PIN (min 4 digits)";
    renderPinDots(); $("nk-submit").classList.add("dim"); return;
  }
  // Re-encrypt vault with new PIN
  const oldKey = STATE.masterKey;
  // We need the old key to decrypt. During PIN reset via SQ, the user was NOT logged in.
  // The vault data is still encrypted with the old key. We'll load with the old hash's password.
  // Actually, we need to find the old PIN. Since we verified SQ, we need to re-encrypt.
  // The data in localStorage is encrypted with the OLD pin. We cannot decrypt without it.
  // So instead: wipe vault data, set new PIN, start fresh.
  // OR: store the master key temporarily after SQ verification.
  // Better approach: SQ recovery resets everything (PIN + wipes vault) for security.
  const newPin = _pin;
  const hash = await Crypto.hashPassword(newPin);
  LS.set("vault_hash", hash);
  STATE.masterKey = newPin;
  STATE.items = [];
  LS.del("vault_data");
  _pin = ""; _pinResetMode = false; _pinResetConfirm = null;
  // Clear biometric since PIN changed
  LS.del("vault_bio_cred"); LS.del("vault_bio_nonce"); LS.del("vault_bio_enc");
  openApp();
  toast("PIN reset — Vault data was cleared for security", "warn");
}

async function sqLockoutUnlock() {
  const answer = $("lb-sq-ans")?.value?.trim() || "";
  if (!answer) return;
  const hash = await hashSQAnswer(answer);
  if (hash !== LS.get("vault_sq_hash")) {
    $("lb-sq-ans").value = "";
    $("lb-sq-ans").classList.add("shake");
    setTimeout(() => $("lb-sq-ans").classList.remove("shake"), 500);
    toast("Wrong answer");
    return;
  }
  // Correct — unlock. But we don't have the PIN. Show PIN reset flow.
  clearFailCount();
  endLockout();
  startPinReset();
  toast("Verified — Create a new PIN", "success");
}

function renderSQSettings() {
  const panel = $("sq-settings-panel");
  if (!panel) return;
  const question = LS.get("vault_sq_question");
  if (question) {
    panel.innerHTML = `<div class="sq-set-card"><div class="sq-set-row">
      <div class="sq-set-ico">🛡️</div>
      <div class="sq-set-info">
        <div class="sq-set-name">${esc(question)}</div>
        <div class="sq-set-sub">Recovery method active ✓</div>
      </div>
      <div class="set-act" onclick="openChangeSQ()">Change</div>
    </div></div>`;
  } else {
    panel.innerHTML = `<div style="font-size:13px;color:var(--muted);margin-bottom:10px">No secret question set. Set one to recover your vault if you forget your PIN.</div>
      <button class="btn primary" style="padding:11px" onclick="openChangeSQ()">Set Secret Question</button>`;
  }
}

function openChangeSQ() {
  const body = $("add-body");
  const foot = $("add-foot");
  $("add-title").textContent = "Secret Question";
  body.innerHTML = `
    <div class="fg">
      <div class="fl">Secret Question</div>
      <select class="fi" id="sq-ch-preset" onchange="document.getElementById('sq-ch-custom-wrap').style.display=this.value==='__custom__'?'':'none'">
        <option value="">— Select a question —</option>
        <option>What is your pet's name?</option>
        <option>What city were you born in?</option>
        <option>What is your mother's maiden name?</option>
        <option>What was your first car?</option>
        <option>What is your favorite movie?</option>
        <option>What school did you first attend?</option>
        <option value="__custom__">✏️ Write my own question…</option>
      </select>
    </div>
    <div class="fg" id="sq-ch-custom-wrap" style="display:none">
      <div class="fl">Your Custom Question</div>
      <input class="fi" id="sq-ch-custom" placeholder="Type your question…">
    </div>
    <div class="fg">
      <div class="fl">Your Answer *</div>
      <input class="fi" id="sq-ch-answer" placeholder="Type your answer…">
      <div style="font-size:10px;color:var(--faint)">Answer is case-insensitive</div>
    </div>`;
  foot.innerHTML = `
    <button class="btn ghost" onclick="closeOverlay('add-overlay')">Cancel</button>
    <button class="btn primary" onclick="saveSQChange()">Save</button>`;
  openOverlay("add-overlay");
}

async function saveSQChange() {
  const sel = $("sq-ch-preset");
  let question = sel.value === "__custom__" ? $("sq-ch-custom").value.trim() : sel.value;
  const answer = $("sq-ch-answer").value.trim();
  if (!question || !answer) { toast("Please fill in question and answer"); return; }
  const hash = await hashSQAnswer(answer);
  LS.set("vault_sq_question", question);
  LS.set("vault_sq_hash", hash);
  closeOverlay("add-overlay");
  renderSQSettings();
  toast("Secret question updated", "success");
}

// -- Biometric (WebAuthn) --
async function isBioAvailable() {
  if (!window.PublicKeyCredential) return false;
  try { return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); }
  catch { return false; }
}

async function offerBioRegistration() {
  if (LS.get("vault_bio_cred") || LS.get("vault_bio_asked")) return;
  if (!await isBioAvailable()) return;
  LS.set("vault_bio_asked", "1");
  // Small delay so the main UI loads first
  setTimeout(() => {
    if (confirm("Enable fingerprint unlock for faster access?")) {
      registerBiometric(STATE.masterKey);
    }
  }, 800);
}

async function registerBiometric(pin) {
  try {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId    = crypto.getRandomValues(new Uint8Array(16));
    const rpId      = location.hostname || "localhost";

    const credential = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: "Vault", id: rpId },
        user: { id: userId, name: "vault-user", displayName: "Vault User" },
        pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          userVerification: "required",
          residentKey: "preferred",
        },
        timeout: 60000,
      }
    });

    const credId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
    LS.set("vault_bio_cred", credId);

    // Store PIN encrypted with a random nonce
    const nonce = crypto.getRandomValues(new Uint8Array(64));
    const pinBytes = new TextEncoder().encode(pin);
    const encrypted = new Uint8Array(pinBytes.length);
    for (let i = 0; i < pinBytes.length; i++) encrypted[i] = pinBytes[i] ^ nonce[i % nonce.length];
    LS.set("vault_bio_nonce", btoa(String.fromCharCode(...nonce)));
    LS.set("vault_bio_enc", btoa(String.fromCharCode(...encrypted)));

    toast("Fingerprint unlock enabled", "success");
  } catch (e) {
    console.warn("Bio registration failed:", e);
    toast("Fingerprint setup failed", "error");
  }
}

let _bioInProgress = false;
async function biometricUnlock() {
  const credId = LS.get("vault_bio_cred");
  if (!credId || _bioInProgress) return;
  _bioInProgress = true;

  try {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const rawId = Uint8Array.from(atob(credId), c => c.charCodeAt(0));
    const rpId  = location.hostname || "localhost";

    await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId,
        allowCredentials: [{ id: rawId, type: "public-key", transports: ["internal"] }],
        userVerification: "required",
        timeout: 60000,
      }
    });

    // Biometric succeeded — recover PIN
    const nonce = Uint8Array.from(atob(LS.get("vault_bio_nonce")), c => c.charCodeAt(0));
    const enc   = Uint8Array.from(atob(LS.get("vault_bio_enc")),   c => c.charCodeAt(0));
    const pinBytes = new Uint8Array(enc.length);
    for (let i = 0; i < enc.length; i++) pinBytes[i] = enc[i] ^ nonce[i % nonce.length];
    const pin = new TextDecoder().decode(pinBytes);

    const hash = await Crypto.hashPassword(pin);
    if (hash === LS.get("vault_hash")) {
      clearFailCount();
      STATE.masterKey = pin;
      await loadItems();
      openApp();
      toast("Unlocked with fingerprint", "success");
    } else {
      // PIN changed since bio was registered
      setLockErr("Fingerprint data outdated — use PIN");
      LS.del("vault_bio_cred"); LS.del("vault_bio_nonce"); LS.del("vault_bio_enc");
      $("bio-section").classList.remove("show");
    }
  } catch (e) {
    setLockErr("Fingerprint cancelled — use PIN");
  } finally {
    _bioInProgress = false;
  }
}

async function autoBiometricUnlock() {
  if (LS.get("vault_bio_cred") && await isBioAvailable()) {
    // Prevent auto-triggering if user is locked out
    if (LS.get("vault_lockout_until") && parseInt(LS.get("vault_lockout_until"), 10) > Date.now()) {
      return;
    }
    setTimeout(() => {
      biometricUnlock();
    }, 350);
  }
}

async function renderBioSettings() {
  const sec = $("bio-settings-sec");
  if (!sec) return;

  const isAvailable = await isBioAvailable();
  const bioToggle = $("bio-toggle");
  const bioDesc = $("bio-status-desc");

  if (!isAvailable) {
    bioToggle.classList.remove("on");
    bioToggle.style.opacity = "0.5";
    bioToggle.style.pointerEvents = "none";
    bioDesc.textContent = "Biometrics not supported or available on this device";
    return;
  }

  bioToggle.style.opacity = "";
  bioToggle.style.pointerEvents = "";
  const hasCred = !!LS.get("vault_bio_cred");
  if (hasCred) {
    bioToggle.classList.add("on");
    bioDesc.textContent = "Biometric unlock is enabled and ready";
  } else {
    bioToggle.classList.remove("on");
    bioDesc.textContent = "Touch to set up biometric fingerprint unlock";
  }
}

async function toggleBiometricSetting() {
  const isAvailable = await isBioAvailable();
  if (!isAvailable) {
    toast("Biometrics not available on this device", "error");
    return;
  }

  const hasCred = !!LS.get("vault_bio_cred");
  if (hasCred) {
    if (confirm("Disable biometric fingerprint unlock?")) {
      LS.del("vault_bio_cred");
      LS.del("vault_bio_nonce");
      LS.del("vault_bio_enc");
      toast("Biometric unlock disabled", "info");
      renderBioSettings();
    }
  } else {
    if (!STATE.masterKey) {
      toast("Unlock vault first to register biometrics", "error");
      return;
    }
    toast("Please authenticate to register biometric unlock...", "info");
    await registerBiometric(STATE.masterKey);
    renderBioSettings();
  }
}

// ══════════════════════════════════════════════════════════
//  GOOGLE DRIVE — OAuth2 implicit flow
// ══════════════════════════════════════════════════════════
function handleOAuthCallback() {
  const hash = location.hash;
  if (!hash.includes("access_token")) return;
  const params = new URLSearchParams(hash.slice(1));
  const token  = params.get("access_token");
  if (!token) return;
  STATE.drive.token = token;
  LS.set("drive_token", token);
  LS.set("drive_connected", "true");
  // Store token expiry (Google sends expires_in in seconds, default 3600)
  const expiresIn = parseInt(params.get("expires_in") || "3600", 10);
  const expiry = Date.now() + expiresIn * 1000;
  STATE.drive.tokenExpiry = expiry;
  LS.set("drive_token_expiry", expiry);
  // Clean URL
  history.replaceState(null, "", location.pathname);

  // Fetch email for login_hint in future silent refreshes
  fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
    headers: { "Authorization": "Bearer " + token }
  })
  .then(res => res.json())
  .then(data => {
    if (data && data.email) LS.set("drive_email", data.email);
  })
  .catch(err => console.error("Could not fetch user email:", err));
}

function isTokenExpired() {
  if (!STATE.drive.tokenExpiry) return false; // no expiry stored, try anyway
  return Date.now() >= STATE.drive.tokenExpiry - 60000; // expired or within 1 min
}

function getOAuthRedirectUri() {
  let redirectUri = location.origin + location.pathname;
  redirectUri = redirectUri.replace(/\/index\.html$/, "/");
  if (!redirectUri.endsWith("/")) redirectUri += "/";
  return redirectUri;
}

// Attempt silent token refresh via hidden iframe (prompt=none)
let _silentRefreshInProgress = false;
function silentTokenRefresh() {
  if (_silentRefreshInProgress) return Promise.resolve(false);
  const clientId = VAULT_CONFIG.GOOGLE_CLIENT_ID;
  if (!clientId || clientId.startsWith("PASTE_")) return Promise.resolve(false);
  _silentRefreshInProgress = true;

  return new Promise((resolve) => {
    const redirectUri = getOAuthRedirectUri();
    const params = new URLSearchParams({
      client_id    : clientId,
      redirect_uri : redirectUri,
      response_type: "token",
      scope        : VAULT_CONFIG.DRIVE_SCOPE + " email",
      prompt       : "none",        // silent — no UI
    });
    const savedEmail = LS.get("drive_email");
    if (savedEmail) {
      params.append("login_hint", savedEmail);
    }
    const authUrl = "https://accounts.google.com/o/oauth2/v2/auth?" + params;

    const iframe = document.createElement("iframe");
    iframe.style.cssText = "display:none;width:0;height:0;border:0";
    iframe.id = "silent-auth-frame";

    const timeout = setTimeout(() => {
      cleanup();
      resolve(false);
    }, 8000);

    function cleanup() {
      clearTimeout(timeout);
      _silentRefreshInProgress = false;
      try { iframe.remove(); } catch {}
    }

    function onMessage(e) {
      // Only accept messages from our own origin
      if (e.origin !== location.origin) return;
      if (e.data?.type === "vault-silent-auth") {
        window.removeEventListener("message", onMessage);
        cleanup();
        if (e.data.token) {
          STATE.drive.token = e.data.token;
          LS.set("drive_token", e.data.token);
          LS.set("drive_connected", "true");
          const expiry = Date.now() + (e.data.expiresIn || 3600) * 1000;
          STATE.drive.tokenExpiry = expiry;
          LS.set("drive_token_expiry", expiry);
          STATE.drive.status = "synced";
          renderSyncBadge();
          console.log("[Vault] Silent token refresh succeeded");
          resolve(true);
        } else {
          resolve(false);
        }
      }
    }
    window.addEventListener("message", onMessage);

    // The iframe will load back to our page with the hash fragment.
    // We need the page to detect it's in an iframe and postMessage back.
    iframe.src = authUrl;
    document.body.appendChild(iframe);

    // Also listen for iframe load to check hash directly
    iframe.addEventListener("load", () => {
      try {
        const iframeHash = iframe.contentWindow.location.hash;
        if (iframeHash && iframeHash.includes("access_token")) {
          const iParams = new URLSearchParams(iframeHash.slice(1));
          const token = iParams.get("access_token");
          if (token) {
            window.removeEventListener("message", onMessage);
            cleanup();
            STATE.drive.token = token;
            LS.set("drive_token", token);
            LS.set("drive_connected", "true");
            const expiresIn = parseInt(iParams.get("expires_in") || "3600", 10);
            const expiry = Date.now() + expiresIn * 1000;
            STATE.drive.tokenExpiry = expiry;
            LS.set("drive_token_expiry", expiry);
            STATE.drive.status = "synced";
            renderSyncBadge();
            console.log("[Vault] Silent token refresh succeeded (iframe load)");
            resolve(true);
            return;
          }
        }
        // If error in hash (e.g., interaction_required), fail silently
        if (iframeHash && iframeHash.includes("error")) {
          window.removeEventListener("message", onMessage);
          cleanup();
          console.log("[Vault] Silent refresh failed:", iframeHash);
          resolve(false);
        }
      } catch (e) {
        // Cross-origin — iframe loaded Google's page, not ours yet
        // Wait for redirect back to our origin
      }
    });
  });
}

function connectDrive() {
  const clientId = VAULT_CONFIG.GOOGLE_CLIENT_ID;
  if (!clientId || clientId.startsWith("PASTE_")) {
    toast("Add your Client ID to config.js first — see SETUP.md");
    return;
  }
  const redirectUri = getOAuthRedirectUri();
  console.log("OAuth redirect_uri:", redirectUri);
  const params = new URLSearchParams({
    client_id    : clientId,
    redirect_uri : redirectUri,
    response_type: "token",
    scope        : VAULT_CONFIG.DRIVE_SCOPE + " email",
    prompt       : "select_account",
  });
  // Redirect in same page — no popup
  const authUrl = "https://accounts.google.com/o/oauth2/v2/auth?" + params;
  location.href = authUrl;
}

function disconnectDrive() {
  STATE.drive.token       = null;
  STATE.drive.tokenExpiry = null;
  STATE.drive.fileId      = null;
  STATE.drive.status      = "offline";
  LS.del("drive_token");
  LS.del("drive_token_expiry");
  LS.del("drive_connected");
  LS.del("drive_file_id");
  LS.del("drive_last_sync");
  LS.del("drive_email");
  renderDrivePanel();
  renderSyncBadge();
  toast("Drive disconnected", "info");
}

async function driveReq(url, opts = {}, _retried = false) {
  // Proactively refresh if token is expired (before wasting a round-trip)
  if (isTokenExpired() && !_retried) {
    console.log("[Vault] Token expired, attempting silent refresh...");
    const refreshed = await silentTokenRefresh();
    if (!refreshed) {
      STATE.drive.token = null;
      LS.del("drive_token");
      LS.del("drive_token_expiry");
      STATE.drive.status = "error";
      renderSyncBadge();
      renderDrivePanel();
      throw new Error("SESSION_EXPIRED");
    }
  }

  const res = await fetch(url, {
    ...opts,
    headers: {
      "Authorization": "Bearer " + STATE.drive.token,
      ...(opts.headers || {}),
    },
  });
  if (res.status === 401 || res.status === 403) {
    // Token expired or insufficient scope — try silent refresh once
    if (!_retried) {
      console.log("[Vault] Got 401/403, attempting silent token refresh...");
      const refreshed = await silentTokenRefresh();
      if (refreshed) {
        return driveReq(url, opts, true); // retry with fresh token
      }
    }
    STATE.drive.token = null;
    STATE.drive.tokenExpiry = null;
    LS.del("drive_token");
    LS.del("drive_token_expiry");
    STATE.drive.status = "error";
    renderSyncBadge();
    renderDrivePanel();
    throw new Error("SESSION_EXPIRED");
  }
  if (!res.ok) {
    throw new Error(`HTTP_ERROR_${res.status}`);
  }
  return res;
}

async function triggerSync() {
  if (!navigator.onLine) {
    setSyncStatus("offline");
    return;
  }
  if (!STATE.drive.token) { toast("Connect Drive first"); return; }
  if (!STATE.masterKey) return;
  setSyncStatus("syncing");
  try {
    await uploadVault();
    const now = new Date().toISOString();
    STATE.drive.lastSync = now;
    LS.set("drive_last_sync", now);
    setSyncStatus("synced");
    toast("Synced to Drive", "success");
    renderDrivePanel();
  } catch (e) {
    setSyncStatus("error");
    if (e.message === "SESSION_EXPIRED") toast("Drive session expired — reconnect", "error");
    else toast("Sync failed: " + e.message, "error");
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
    const q   = encodeURIComponent(`name='${VAULT_CONFIG.DRIVE_FILE_NAME}'`);
    const res = await driveReq(`https://www.googleapis.com/drive/v3/files?q=${q}&spaces=appDataFolder&fields=files(id)`);
    const dat = await res.json();
    if (dat.files?.length) {
      STATE.drive.fileId = dat.files[0].id;
      LS.set("drive_file_id", STATE.drive.fileId);
    }
  }

  if (STATE.drive.fileId) {
    // Update
    try {
      await driveReq(
        `https://www.googleapis.com/upload/drive/v3/files/${STATE.drive.fileId}?uploadType=media`,
        { method:"PATCH", headers:{"Content-Type":"application/json"}, body:payload }
      );
      return;
    } catch (e) {
      if (e.message.includes("404")) {
        STATE.drive.fileId = null;
        LS.del("drive_file_id");
      } else {
        throw e;
      }
    }
  }

  // Create
  const res = await driveReq("https://www.googleapis.com/drive/v3/files", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: VAULT_CONFIG.DRIVE_FILE_NAME, parents: ["appDataFolder"] })
  });
  const dat = await res.json();
  STATE.drive.fileId = dat.id;
  LS.set("drive_file_id", STATE.drive.fileId);

  await driveReq(
    `https://www.googleapis.com/upload/drive/v3/files/${STATE.drive.fileId}?uploadType=media`,
    { method:"PATCH", headers:{"Content-Type":"application/json"}, body:payload }
  );
}

async function pullFromDrive() {
  if (!navigator.onLine) {
    setSyncStatus("offline");
    return false;
  }
  if (!STATE.drive.token) { toast("Connect Drive first"); return false; }
  setSyncStatus("syncing");
  try {
    let fileId = STATE.drive.fileId;
    if (!fileId) {
      const q   = encodeURIComponent(`name='${VAULT_CONFIG.DRIVE_FILE_NAME}'`);
      const res = await driveReq(`https://www.googleapis.com/drive/v3/files?q=${q}&spaces=appDataFolder&fields=files(id)`);
      const dat = await res.json();
      if (!dat.files?.length) { toast("No backup found on Drive"); setSyncStatus("synced"); return true; }
      fileId = dat.files[0].id;
      STATE.drive.fileId = fileId;
      LS.set("drive_file_id", fileId);
    }
    let payload;
    try {
      const res = await driveReq(`https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`);
      payload = await res.json();
    } catch (e) {
      if (e.message.includes("404")) {
        STATE.drive.fileId = null;
        LS.del("drive_file_id");
        throw new Error("Backup file not found on Drive");
      }
      throw e;
    }

    if (!payload.vault) throw new Error("Invalid backup");
    const imported = await Crypto.decrypt(payload.vault, STATE.masterKey);
    let added = 0;
    let updated = 0;
    for (const item of imported) {
      const existingIdx = STATE.items.findIndex(i => i.id === item.id);
      if (existingIdx === -1) { 
        STATE.items.push(item); 
        if (!item.deleted) added++; 
      } else {
        const existing = STATE.items[existingIdx];
        if ((item.updated || 0) > (existing.updated || 0)) {
          STATE.items[existingIdx] = item;
          if (!item.deleted) updated++;
        }
      }
    }
    await persistItems();
    renderAll(); updateStats();
    setSyncStatus("synced");
    const now = new Date().toISOString();
    STATE.drive.lastSync = now; LS.set("drive_last_sync", now);
    if (added > 0 || updated > 0) {
      toast(`Pulled ${added} new, ${updated} updated items`, "success");
    } else {
      toast("Vault is up to date", "info");
    }
    renderDrivePanel();
    return true;
  } catch (e) {
    setSyncStatus("error");
    if (e.message === "SESSION_EXPIRED") toast("Drive session expired — reconnect", "error");
    else if (e.message === "Failed to fetch") toast("Offline — using local vault", "info");
    else toast("Pull failed: " + e.message, "error");
    return false;
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
  const map = { offline:"Local", syncing:"Syncing…", synced:"Drive ✓", error:"Sync Error", noconfig:"No Drive" };
  label.textContent = map[s] || s;
}

function handleSyncBadgeClick() {
  if (!navigator.onLine) {
    toast("No internet connection", "info");
    return;
  }
  const s = STATE.drive.status;
  if (s === "error" || (LS.get("drive_connected") === "true" && !STATE.drive.token)) {
    connectDrive();
  } else if (s === "offline") {
    toggleSettings(true);
    setTimeout(() => {
      $("drive-panel")?.scrollIntoView({ behavior: "smooth" });
    }, 200);
  } else if (STATE.drive.token) {
    triggerSync();
  }
}

function renderDrivePanel() {
  const panel = $("drive-panel");
  if (!panel) return;
  const { token, lastSync, status } = STATE.drive;
  const configured = VAULT_CONFIG.GOOGLE_CLIENT_ID && !VAULT_CONFIG.GOOGLE_CLIENT_ID.startsWith("PASTE_");
  const syncTime   = lastSync ? new Date(lastSync).toLocaleString() : "Never";

  if (!configured) {
    panel.innerHTML = driveRow("⚙️","Not configured","Add your Client ID to config.js — see SETUP.md","","");
    return;
  }

  if (token) {
    panel.innerHTML =
      driveRow("☁️","Google Drive","Connected · Last sync: "+syncTime,
        `<span class="dr-act sync" onclick="triggerSync()">Sync Now</span>`) +
      driveRow("⬇️","Pull from Drive","Merge cloud backup into local vault",
        `<span class="dr-act pull" onclick="pullFromDrive()">Pull</span>`) +
      driveRow("🔌","Disconnect","Remove Drive access",
        `<span class="dr-act disc" onclick="disconnectDrive()">Remove</span>`);
  } else if (LS.get("drive_connected") === "true") {
    panel.innerHTML =
      driveRow("⚠️","Session Expired","Please reconnect to resume syncing",
        `<span class="dr-act connect" onclick="connectDrive()">Reconnect</span>`) +
      driveRow("🔌","Disconnect","Remove Drive access",
        `<span class="dr-act disc" onclick="disconnectDrive()">Remove</span>`);
  } else {
    panel.innerHTML =
      driveRow("☁️","Google Drive","Not connected · Sync vault across devices",
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

// ══════════════════════════════════════════════════════════
//  ITEMS
// ══════════════════════════════════════════════════════════
function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

async function saveItem(item) {
  item.updated = Date.now();
  const idx = STATE.items.findIndex(i => i.id === item.id);
  if (idx >= 0) STATE.items[idx] = item; else STATE.items.push(item);
  await persistItems();
  if (STATE.drive.token) triggerSync();
}

async function removeItem(id) {
  const item = STATE.items.find(i => i.id === id);
  if (item) {
    item.deleted = true;
    item.updated = Date.now();
  } else {
    STATE.items.push({ id, deleted: true, updated: Date.now() });
  }
  await persistItems();
  if (STATE.drive.token) triggerSync();
  renderAll(); renderTagStrip(); updateStats();
}

// ══════════════════════════════════════════════════════════
//  RENDER — LIST
// ══════════════════════════════════════════════════════════
function timeAgo(ts) {
  if (!ts) return "";
  const diff = Date.now() - ts;
  const sec = Math.floor(diff / 1000);
  if (sec < 60)    return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60)    return min + "m ago";
  const hr = Math.floor(min / 60);
  if (hr < 24)     return hr + "h ago";
  const day = Math.floor(hr / 24);
  if (day < 30)    return day + "d ago";
  const mo = Math.floor(day / 30);
  if (mo < 12)     return mo + "mo ago";
  return Math.floor(mo / 12) + "y ago";
}

function sameDay(a, b) {
  if (!a || !b) return true;
  const da = new Date(a), db = new Date(b);
  return da.getFullYear() === db.getFullYear() && da.getMonth() === db.getMonth() && da.getDate() === db.getDate();
}

function getItemAge(item) {
  if (!item.updated || sameDay(item.created, item.updated)) {
    return timeAgo(item.created);
  }
  return "edited " + timeAgo(item.updated);
}

const T_ICON  = { password:"🔑", bookmark:"🔖", note:"📝", todo:"✅" };
const T_CLASS = { password:"ip", bookmark:"ib", note:"in", todo:"it" };
const ITEM_TYPES = ["all", "password", "bookmark", "note", "todo"];

const TODO_COLORS = [
  { name:"red",    hex:"#f87171" },
  { name:"orange", hex:"#fb923c" },
  { name:"amber",  hex:"#fbbf24" },
  { name:"green",  hex:"#4ade80" },
  { name:"teal",   hex:"#2dd4bf" },
  { name:"blue",   hex:"#60a5fa" },
  { name:"purple", hex:"#7c6af5" },
  { name:"pink",   hex:"#f472b6" },
];

function getAllTags() {
  const s = new Set();
  STATE.items.forEach(i => {
    if (!i.deleted) (i.tags||[]).forEach(t => s.add(t));
  });
  return [...s].sort();
}

function toggleFavFilter() {
  STATE.favOnly = !STATE.favOnly;
  $("fav-btn").classList.toggle("on", STATE.favOnly);
  renderList();
}

function switchTab(el, t) {
  STATE.tab = t;
  STATE.typeFilter = null;
  STATE.focusedActiveTagIndex = -1;
  STATE.focusedSearchButtonIndex = -1;
  updateSearchButtonsHighlight();
  // Close any expanded items when switching tabs
  STATE.expandedId = null;
  STATE.pwVisible = {};
  _dashExpanded = null;
  document.querySelectorAll(".nav-item").forEach(e => e.classList.remove("on"));
  el.classList.add("on");
  const isDash = t === "dash";
  const dashEl = $("dashboard");
  const listEl = $("list");
  const searchEl = $("search-row");
  const tagEl = $("tag-filter-row");
  if (isDash) {
    if (dashEl) dashEl.style.display = "flex";
    if (listEl) listEl.style.display = "none";
    if (searchEl) searchEl.style.display = "none";
    if (tagEl) tagEl.style.display = "none";
    renderDashboard();
  } else {
    if (dashEl) dashEl.style.display = "none";
    if (listEl) listEl.style.display = "flex";
    if (searchEl) searchEl.style.display = "";
    if (tagEl) tagEl.style.display = "";
    renderList();
  }
}

function onSearch(inp) {
  $("q-clear").style.display = inp.value ? "block" : "none";
  
  // Mobile-safe comma listener: if input ends with a comma, commit it as a tag immediately
  if (inp.value && inp.value.endsWith(",")) {
    // If we have matching suggestions, select the active highlighted tag pill
    if (STATE.suggestions && STATE.suggestions.length > 0) {
      const idx = STATE.focusedSuggestionIndex >= 0 ? STATE.focusedSuggestionIndex : 0;
      selectSuggestion(idx);
      return;
    }
    
    let tagText = inp.value.slice(0, -1).trim();
    if (tagText.startsWith("#")) tagText = tagText.slice(1);
    tagText = tagText.trim();
    if (tagText) {
      const allTags = getAllTags();
      const matchedTag = allTags.find(t => t.toLowerCase() === tagText.toLowerCase());
      if (matchedTag) {
        inp.value = "";
        $("q-clear").style.display = "none";
        if (!STATE.activeTags.includes(matchedTag)) {
          STATE.activeTags.push(matchedTag);
          renderSelectedTags();
          renderList();
          toast(`Added tag filter: #${matchedTag}`, "success");
        }
        generateSuggestions("");
      }
      return;
    }
  }

  generateSuggestions(inp.value);
  debouncedRenderList();
}

function onSearchFocus(inp) {
  generateSuggestions(inp.value);
}

// Close suggestions dropdown when clicking outside and reset tag/button focus
document.addEventListener("click", (e) => {
  const suggestEl = $("search-suggestions");
  const qEl = $("q");
  if (suggestEl && qEl && !suggestEl.contains(e.target) && e.target !== qEl) {
    suggestEl.style.display = "none";
  }
  
  const selectedTagsEl = document.getElementById("selected-tags");
  const searchRowEl = document.getElementById("search-row");
  
  if (qEl && e.target !== qEl) {
    if (selectedTagsEl && !selectedTagsEl.contains(e.target)) {
      if (STATE.focusedActiveTagIndex !== -1) {
        STATE.focusedActiveTagIndex = -1;
        renderSelectedTags();
      }
    }
    if (searchRowEl && !searchRowEl.contains(e.target)) {
      if (STATE.focusedSearchButtonIndex !== -1) {
        STATE.focusedSearchButtonIndex = -1;
        updateSearchButtonsHighlight();
      }
    }
  }
});

function generateSuggestions(query) {
  const suggestEl = $("search-suggestions");
  if (!suggestEl) return;
  
  const q = (query || "").trim().toLowerCase();
  
  // Reset navigation index
  STATE.focusedSuggestionIndex = -1;
  STATE.suggestions = [];
  
  // Hide suggestions completely if suggest is disabled and search query is empty
  if (!STATE.autoSuggest && !q) {
    suggestEl.style.display = "none";
    return;
  }
  
  const allItems = STATE.items.filter(i => !i.deleted);
  
  let matchingTags = [];
  let matchingTitles = [];
  let matchingUsernames = [];
  let matchingNotes = [];
  let matchingTypes = [];
  
  const cleanQ = q.startsWith("#") ? q.slice(1) : q;
  
  const typeMap = {
    "passwords": "password",
    "bookmarks": "bookmark",
    "notes": "note",
    "todos": "todo"
  };
  const mappedQ = typeMap[cleanQ] || cleanQ;
  
  if (q) {
    // Match Types
    matchingTypes = ITEM_TYPES
      .filter(t => t.includes(mappedQ) && t !== STATE.tab && t !== STATE.typeFilter)
      .map(t => ({ type: "item-type", text: t }));

    // Match Tags
    const allTags = getAllTags();
    matchingTags = allTags
      .filter(t => t.toLowerCase().includes(cleanQ) && 
                   !STATE.activeTags.includes(t) && 
                   t.toLowerCase() !== STATE.typeFilter && 
                   t.toLowerCase() !== STATE.tab)
      .map(t => {
        const count = allItems.filter(i => (i.tags || []).includes(t)).length;
        return { type: "tag", text: t, count };
      })
      .slice(0, 8);
      
    // Match Titles, Usernames, Notes only if autoSuggest is enabled
    if (STATE.autoSuggest) {
      matchingTitles = allItems
        .filter(i => i.title && i.title.toLowerCase().includes(q))
        .slice(0, 5)
        .map(i => ({ type: "title", text: i.title, item: i }));
        
      matchingUsernames = allItems
        .filter(i => i.username && i.username.toLowerCase().includes(q))
        .slice(0, 5)
        .map(i => ({ type: "username", text: i.username, item: i }));
        
      if (STATE.deepSearch) {
        matchingNotes = allItems
          .filter(i => i.note && i.note.toLowerCase().includes(q))
          .slice(0, 5)
          .map(i => {
            const idx = i.note.toLowerCase().indexOf(q);
            const start = Math.max(0, idx - 20);
            const end = Math.min(i.note.length, idx + q.length + 20);
            let snippet = i.note.slice(start, end).replace(/\n/g, " ");
            if (start > 0) snippet = "..." + snippet;
            if (end < i.note.length) snippet = snippet + "...";
            return { type: "note", text: snippet, item: i, rawText: q };
          });
      }
    }
  } else {
    // Show top tags when search is empty ONLY if autoSuggest is enabled
    if (STATE.autoSuggest) {
      matchingTypes = ITEM_TYPES
        .filter(t => t !== STATE.tab && t !== STATE.typeFilter)
        .map(t => ({ type: "item-type", text: t }));
      const allTags = getAllTags();
      matchingTags = allTags
        .filter(t => !STATE.activeTags.includes(t))
        .map(t => {
          const count = allItems.filter(i => (i.tags || []).includes(t)).length;
          return { type: "tag", text: t, count };
        })
        .slice(0, 8);
    }
  }
  
  // Combine suggestions
  STATE.suggestions = [...matchingTypes, ...matchingTags, ...matchingTitles, ...matchingUsernames, ...matchingNotes];
  
  if (STATE.suggestions.length === 0) {
    if (q && STATE.autoSuggest) {
      suggestEl.classList.remove("tags-only");
      suggestEl.innerHTML = `<div class="suggest-empty">No suggestions found for "${esc(query)}"</div>`;
      suggestEl.style.display = "flex";
    } else {
      suggestEl.style.display = "none";
    }
    return;
  }
  
  // Render html
  let html = "";
  
  // If autoSuggest is disabled: Render ONLY tags/types in horizontal pill row format
  if (!STATE.autoSuggest) {
    suggestEl.classList.add("tags-only");
    STATE.focusedSuggestionIndex = -1; // Do not auto-highlight, allows arrow keys to work
    
    html += `<div class="suggest-tags-row">`;
    STATE.suggestions.forEach((t, idx) => {
      const isType = t.type === "item-type";
      const name = isType ? `Type: ${t.text}` : t.text;
      const matchText = isType ? t.text : name;
      const matchIdx = matchText.toLowerCase().indexOf(cleanQ);
      let renderedName = esc(name);
      if (matchIdx >= 0 && cleanQ) {
        const prefix = isType ? "Type: " : "";
        const offset = prefix.length;
        const actualMatchStart = matchIdx + offset;
        renderedName = esc(name.slice(0, actualMatchStart)) + 
                       `<mark class="match-highlight">${esc(name.slice(actualMatchStart, actualMatchStart + cleanQ.length))}</mark>` + 
                       esc(name.slice(actualMatchStart + cleanQ.length));
      }
      const activeClass = idx === STATE.focusedSuggestionIndex ? "active-highlight" : "";
      if (isType) {
        html += `
          <span class="suggest-tag-pill type-pill ${activeClass}" onclick="selectSuggestion(${idx})" id="suggest-item-${idx}">
            <span class="pill-hash">⚙️</span>${renderedName}
          </span>
        `;
      } else {
        html += `
          <span class="suggest-tag-pill ${activeClass}" onclick="selectSuggestion(${idx})" id="suggest-item-${idx}">
            <span class="pill-hash">#</span>${renderedName}
            <span class="pill-count">${t.count}</span>
          </span>
        `;
      }
    });
    html += `</div>`;
    suggestEl.innerHTML = html;
    suggestEl.style.display = "flex";
    return;
  }
  
  // Otherwise, standard suggestions dropdown (when suggest toggle is on)
  suggestEl.classList.remove("tags-only");
  
  // Render item types group
  if (matchingTypes.length > 0) {
    html += `<div class="suggest-group">
      <div class="suggest-header">Item Types</div>`;
    matchingTypes.forEach(t => {
      const idx = STATE.suggestions.indexOf(t);
      const icon = T_ICON[t.text] || "📁";
      html += `
        <div class="suggestion-item" onclick="selectSuggestion(${idx})" id="suggest-item-${idx}">
          <div class="suggest-left">
            <span class="suggest-icon">${icon}</span>
            <span class="suggest-text">${highlightMatch(t.text, q)}</span>
            <span class="suggest-subtext">Filter by type</span>
          </div>
        </div>`;
    });
    html += `</div>`;
  }
  
  // Render tags group
  if (matchingTags.length > 0) {
    html += `<div class="suggest-group">
      <div class="suggest-header">Tags</div>`;
    matchingTags.forEach(t => {
      const idx = STATE.suggestions.indexOf(t);
      html += `
        <div class="suggestion-item" onclick="selectSuggestion(${idx})" id="suggest-item-${idx}">
          <div class="suggest-left">
            <span class="suggest-icon">🏷️</span>
            <span class="suggest-text">${highlightMatch(t.text, q)}</span>
          </div>
          <span class="suggest-badge">${t.count} items</span>
        </div>`;
    });
    html += `</div>`;
  }
  
  // Render titles group
  if (matchingTitles.length > 0) {
    html += `<div class="suggest-group">
      <div class="suggest-header">Titles</div>`;
    matchingTitles.forEach(t => {
      const idx = STATE.suggestions.indexOf(t);
      const icon = T_ICON[t.item.type] || "📄";
      html += `
        <div class="suggestion-item" onclick="selectSuggestion(${idx})" id="suggest-item-${idx}">
          <div class="suggest-left">
            <span class="suggest-icon">${icon}</span>
            <span class="suggest-text">${highlightMatch(t.text, q)}</span>
            <span class="suggest-subtext">${esc(t.item.username || t.item.url || "")}</span>
          </div>
        </div>`;
    });
    html += `</div>`;
  }
  
  // Render usernames group
  if (matchingUsernames.length > 0) {
    html += `<div class="suggest-group">
      <div class="suggest-header">Usernames</div>`;
    matchingUsernames.forEach(t => {
      const idx = STATE.suggestions.indexOf(t);
      html += `
        <div class="suggestion-item" onclick="selectSuggestion(${idx})" id="suggest-item-${idx}">
          <div class="suggest-left">
            <span class="suggest-icon">👤</span>
            <span class="suggest-text">${highlightMatch(t.text, q)}</span>
            <span class="suggest-subtext">in ${esc(t.item.title)}</span>
          </div>
        </div>`;
    });
    html += `</div>`;
  }
  
  // Render notes group
  if (matchingNotes.length > 0) {
    html += `<div class="suggest-group">
      <div class="suggest-header">Notes & Descriptions</div>`;
    matchingNotes.forEach(t => {
      const idx = STATE.suggestions.indexOf(t);
      html += `
        <div class="suggestion-item" onclick="selectSuggestion(${idx})" id="suggest-item-${idx}">
          <div class="suggest-left" style="width: 100%">
            <span class="suggest-icon">📝</span>
            <span class="suggest-text" style="font-size:11px; font-family:var(--mono); color:var(--muted)">${highlightMatch(t.text, q)}</span>
            <span class="suggest-subtext" style="margin-left:auto; flex-shrink:0; font-weight:600">in ${esc(t.item.title)}</span>
          </div>
        </div>`;
    });
    html += `</div>`;
  }
  
  suggestEl.innerHTML = html;
  suggestEl.style.display = "flex";
}

function highlightMatch(text, query) {
  if (!query) return esc(text);
  const cleanQ = query.startsWith("#") ? query.slice(1) : query;
  const regex = new RegExp(`(${escapeRegExp(cleanQ)})`, "gi");
  return esc(text).replace(regex, `<mark class="match-highlight">$1</mark>`);
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
function onSearchKeyDown(e) {
  const qEl = $("q");
  if (!qEl) return;

  const SEARCH_BUTTONS = ["suggest-btn", "deep-btn", "fav-btn"];

  // Handle active search buttons focus/action
  if (STATE.focusedSearchButtonIndex !== -1) {
    if (e.key === "ArrowLeft") {
      e.preventDefault();
      STATE.focusedSearchButtonIndex--;
      if (STATE.focusedSearchButtonIndex === -1) {
        if (document.activeElement !== qEl) qEl.focus();
      }
      updateSearchButtonsHighlight();
      return;
    } else if (e.key === "ArrowRight") {
      e.preventDefault();
      STATE.focusedSearchButtonIndex = Math.min(SEARCH_BUTTONS.length - 1, STATE.focusedSearchButtonIndex + 1);
      updateSearchButtonsHighlight();
      return;
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      const btnId = SEARCH_BUTTONS[STATE.focusedSearchButtonIndex];
      const btn = $(btnId);
      if (btn) btn.click();
      return;
    } else if (e.key === "Escape") {
      e.preventDefault();
      STATE.focusedSearchButtonIndex = -1;
      updateSearchButtonsHighlight();
      if (document.activeElement !== qEl) qEl.focus();
      return;
    } else {
      STATE.focusedSearchButtonIndex = -1;
      updateSearchButtonsHighlight();
      if (document.activeElement !== qEl) qEl.focus();
    }
  }

  const items = document.querySelectorAll(".suggestion-item, .suggest-tag-pill");

  // Build active items list for tag selection
  const activeItems = [];
  if (STATE.typeFilter) {
    activeItems.push({ type: "type", value: STATE.typeFilter });
  }
  STATE.activeTags.forEach(t => {
    activeItems.push({ type: "tag", value: t });
  });

  // Handle active tag focus and removal via Backspace / Left / Right Arrow keys
  if (qEl.selectionStart === 0 && qEl.selectionEnd === 0) {
    if (e.key === "Backspace") {
      if (activeItems.length > 0) {
        e.preventDefault();
        if (STATE.focusedActiveTagIndex === -1) {
          // Focus the last item
          STATE.focusedActiveTagIndex = activeItems.length - 1;
          renderSelectedTags();
        } else {
          // Delete the focused item
          const item = activeItems[STATE.focusedActiveTagIndex];
          if (item.type === "type") {
            STATE.typeFilter = null;
          } else {
            STATE.activeTags = STATE.activeTags.filter(t => t !== item.value);
          }
          // Adjust focus index
          const newLength = activeItems.length - 1;
          if (newLength === 0) {
            STATE.focusedActiveTagIndex = -1;
          } else {
            STATE.focusedActiveTagIndex = Math.min(newLength - 1, STATE.focusedActiveTagIndex);
          }
          renderSelectedTags();
          renderList();
        }
        return;
      }
    } else if (e.key === "ArrowLeft") {
      if (activeItems.length > 0) {
        e.preventDefault();
        if (STATE.focusedActiveTagIndex === -1) {
          STATE.focusedActiveTagIndex = activeItems.length - 1;
        } else {
          STATE.focusedActiveTagIndex = Math.max(0, STATE.focusedActiveTagIndex - 1);
        }
        renderSelectedTags();
        return;
      }
    } else if (e.key === "ArrowRight") {
      if (STATE.focusedActiveTagIndex !== -1) {
        e.preventDefault();
        STATE.focusedActiveTagIndex++;
        if (STATE.focusedActiveTagIndex >= activeItems.length) {
          STATE.focusedActiveTagIndex = -1;
        }
        renderSelectedTags();
        return;
      }
    }
  }

  // Handle focusing buttons from search input
  if (qEl.selectionStart === qEl.value.length && qEl.selectionEnd === qEl.value.length) {
    if (e.key === "ArrowRight") {
      e.preventDefault();
      STATE.focusedSearchButtonIndex = 0;
      updateSearchButtonsHighlight();
      if (document.activeElement !== qEl) qEl.focus();
      return;
    }
  }

  // Reset tag focus if they type or press other keys
  if (e.key !== "ArrowLeft" && e.key !== "ArrowRight" && e.key !== "Backspace") {
    if (STATE.focusedActiveTagIndex !== -1) {
      STATE.focusedActiveTagIndex = -1;
      renderSelectedTags();
    }
  }

  // Tab, Enter, or Comma adds/selects tags
  if (e.key === "," || e.key === "Tab" || e.key === "Enter") {
    // If a suggestion pill/item is highlighted, select it
    if (STATE.focusedSuggestionIndex >= 0 && STATE.focusedSuggestionIndex < items.length) {
      e.preventDefault();
      selectSuggestion(STATE.focusedSuggestionIndex);
      return;
    }

    // Otherwise, convert the current input string into a tag filter directly or switch tab if it matches an item type
    const val = qEl.value.trim();
    if (val) {
      e.preventDefault();
      let tagText = val.startsWith("#") ? val.slice(1) : val;
      if (tagText.endsWith(",")) tagText = tagText.slice(0, -1);
      tagText = tagText.trim().toLowerCase();

      const typeMap = {
        "passwords": "password",
        "bookmarks": "bookmark",
        "notes": "note",
        "todos": "todo"
      };
      let normalizedType = typeMap[tagText] || tagText;

      if (ITEM_TYPES.includes(normalizedType)) {
        qEl.value = "";
        $("q-clear").style.display = "none";
        if (STATE.tab === "all") {
          STATE.typeFilter = normalizedType === "all" ? null : normalizedType;
          renderSelectedTags();
          renderList();
          toast(normalizedType === "all" ? "Showing all item types" : `Filtering by type: ${normalizedType.toUpperCase()}`, "success");
        } else {
          const navEl = Array.from(document.querySelectorAll("#nav .nav-item")).find(el => {
            return el.getAttribute("onclick")?.includes(`'${normalizedType}'`);
          });
          if (navEl) {
            switchTab(navEl, normalizedType);
            toast(`Switched tab to: ${normalizedType.toUpperCase()}`, "success");
          }
        }
        generateSuggestions("");
        return;
      }

      tagText = val.startsWith("#") ? val.slice(1) : val;
      if (tagText.endsWith(",")) tagText = tagText.slice(0, -1);
      tagText = tagText.trim();
      if (tagText) {
        const allTags = getAllTags();
        const matchedTag = allTags.find(t => t.toLowerCase() === tagText.toLowerCase());
        if (matchedTag) {
          qEl.value = "";
          $("q-clear").style.display = "none";
          if (!STATE.activeTags.includes(matchedTag)) {
            STATE.activeTags.push(matchedTag);
            renderSelectedTags();
            renderList();
            toast(`Added tag filter: #${matchedTag}`, "success");
          }
          generateSuggestions("");
        }
      }
      return;
    }
  }

  if (items.length === 0) return;

  // Horizontal navigation for tags, vertical for list suggestions
  if (!STATE.autoSuggest) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      STATE.focusedSuggestionIndex = (STATE.focusedSuggestionIndex + 1) % items.length;
      updateSuggestionHighlight(items);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      STATE.focusedSuggestionIndex = (STATE.focusedSuggestionIndex - 1 + items.length) % items.length;
      updateSuggestionHighlight(items);
    } else if (e.key === "Escape") {
      const suggestEl = $("search-suggestions");
      if (suggestEl) suggestEl.style.display = "none";
      qEl.blur();
    }
  } else {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      STATE.focusedSuggestionIndex = (STATE.focusedSuggestionIndex + 1) % items.length;
      updateSuggestionHighlight(items);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      STATE.focusedSuggestionIndex = (STATE.focusedSuggestionIndex - 1 + items.length) % items.length;
      updateSuggestionHighlight(items);
    } else if (e.key === "Escape") {
      const suggestEl = $("search-suggestions");
      if (suggestEl) suggestEl.style.display = "none";
      qEl.blur();
    }
  }
}

function updateSuggestionHighlight(domItems) {
  domItems.forEach((el, idx) => {
    if (idx === STATE.focusedSuggestionIndex) {
      el.classList.add("active");
      el.classList.add("active-highlight");
      el.scrollIntoView({ block: "nearest" });
    } else {
      el.classList.remove("active");
      el.classList.remove("active-highlight");
    }
  });
}

function updateSearchButtonsHighlight() {
  const SEARCH_BUTTONS = ["suggest-btn", "deep-btn", "fav-btn"];
  SEARCH_BUTTONS.forEach((id, idx) => {
    const btn = $(id);
    if (!btn) return;
    if (idx === STATE.focusedSearchButtonIndex) {
      btn.classList.add("focused");
    } else {
      btn.classList.remove("focused");
    }
  });
}

function selectSuggestion(index) {
  const item = STATE.suggestions[index];
  if (!item) return;
  
  const suggestEl = $("search-suggestions");
  if (suggestEl) suggestEl.style.display = "none";
  
  // Clear suggestions state
  STATE.focusedSuggestionIndex = -1;
  STATE.suggestions = [];
  
  const qEl = $("q");
  if (item.type === "tag") {
    if (qEl) {
      qEl.value = "";
      qEl.focus();
    }
    $("q-clear").style.display = "none";
    if (!STATE.activeTags.includes(item.text)) {
      STATE.activeTags.push(item.text);
      renderSelectedTags();
      renderList();
    }
    if (qEl) {
      setTimeout(() => { qEl.value = ""; qEl.focus(); }, 0);
    }
  } else if (item.type === "item-type") {
    const t = item.text;
    if (qEl) {
      qEl.value = "";
      qEl.focus();
    }
    $("q-clear").style.display = "none";
    if (STATE.tab === "all") {
      STATE.typeFilter = t === "all" ? null : t;
      renderSelectedTags();
      renderList();
      toast(t === "all" ? "Showing all item types" : `Filtering by type: ${t.toUpperCase()}`, "success");
    } else {
      const navEl = Array.from(document.querySelectorAll("#nav .nav-item")).find(el => {
        return el.getAttribute("onclick")?.includes(`'${t}'`);
      });
      if (navEl) {
        switchTab(navEl, t);
        toast(`Switched tab to: ${t.toUpperCase()}`, "success");
      }
    }
    if (qEl) {
      setTimeout(() => { qEl.value = ""; qEl.focus(); }, 0);
    }
  } else if (item.type === "title") {
    if (qEl) {
      qEl.value = item.text;
      qEl.focus();
    }
    $("q-clear").style.display = "block";
    renderList();
  } else if (item.type === "username") {
    if (qEl) {
      qEl.value = item.text;
      qEl.focus();
    }
    $("q-clear").style.display = "block";
    renderList();
  } else if (item.type === "note") {
    if (qEl) {
      qEl.value = item.item.title;
      qEl.focus();
    }
    $("q-clear").style.display = "block";
    renderList();
  }
}

function toggleDeepSearch() {
  STATE.deepSearch = !STATE.deepSearch;
  const btn = $("deep-btn");
  if (btn) btn.classList.toggle("on", STATE.deepSearch);
  const qEl = $("q");
  if (qEl) generateSuggestions(qEl.value);
  renderList();
  toast(STATE.deepSearch ? "Deep search enabled 🔍" : "Deep search disabled", "info");
}

function toggleAutoSuggest() {
  STATE.autoSuggest = !STATE.autoSuggest;
  const btn = $("suggest-btn");
  if (btn) btn.classList.toggle("on", STATE.autoSuggest);
  const qEl = $("q");
  if (qEl) generateSuggestions(qEl.value);
  toast(STATE.autoSuggest ? "Autocomplete suggestions enabled ✨" : "Autocomplete disabled (tags only)", "info");
}



function toggleTagMatchStrategy() {
  STATE.tagMatchStrategy = STATE.tagMatchStrategy === "and" ? "or" : "and";
  renderSelectedTags();
  renderList();
  toast(`Tag matching strategy: ${STATE.tagMatchStrategy === "and" ? "ALL (AND)" : "ANY (OR)"}`, "info");
}

function clearSearch() {
  $("q").value = "";
  $("q-clear").style.display = "none";
  const suggestEl = $("search-suggestions");
  if (suggestEl) suggestEl.style.display = "none";
  renderList();
}

// Debounced search for performance
let _searchTimer = null;
function debouncedRenderList() {
  clearTimeout(_searchTimer);
  _searchTimer = setTimeout(() => renderList(), 150);
}

function getItemUrgency(item) {
  const fd = item.flagDate;
  if (fd) {
    const days = (new Date(fd).getTime() - Date.now()) / 86400000;
    if (days < 0)   return 0;
    if (days < 1)   return 1;
    if (days < 3)   return 2;
    if (days < 7)   return 3;
    if (days < 30)  return 4;
  }
  if (item.priority === "high") return 5;
  if (item.priority === "medium") return 6;
  if (item.priority === "low") return 8;
  return 7;
}

function filtered() {
  const q = ($("q")?.value || "").toLowerCase().trim();
  let r = STATE.items.filter(i => {
    if (i.deleted) return false;
    if (STATE.tab !== "all" && STATE.tab !== "dash" && i.type !== STATE.tab) return false;
    if (STATE.tab === "all" && STATE.typeFilter && i.type !== STATE.typeFilter) return false;
    if (STATE.favOnly && !i.fav) return false;
    
    // Tag matching strategy (AND / OR)
    if (STATE.activeTags.length > 0) {
      if (STATE.tagMatchStrategy === "and") {
        if (!STATE.activeTags.every(t => (i.tags||[]).includes(t))) return false;
      } else {
        if (!STATE.activeTags.some(t => (i.tags||[]).includes(t))) return false;
      }
    }
    
    if (!q) return true;
    
    // Prefix tag matching directly in search
    if (q.startsWith("#")) {
      const tagSearch = q.slice(1);
      return (i.tags||[]).some(t => t.toLowerCase().includes(tagSearch));
    }
    
    // Check if query matches the item type (singular or plural forms)
    const typeQueryMap = {
      "password": "password", "passwords": "password",
      "bookmark": "bookmark", "bookmarks": "bookmark",
      "note": "note", "notes": "note",
      "todo": "todo", "todos": "todo"
    };
    if (typeQueryMap[q]) {
      return i.type === typeQueryMap[q];
    }

    const fieldsToSearch = STATE.deepSearch 
      ? [i.title, i.username, i.url, i.note] 
      : [i.title, i.username, i.url];
      
    return [...fieldsToSearch, ...(i.tags||[])].some(v => (v||"").toLowerCase().includes(q));
  });
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
  // Update FAB pulse based on items
  updateFabPulse();
  if (!list.length) {
    const icons = { all:"🔐", password:"🔑", todo:"✅", bookmark:"🔖", note:"📝" };
    const labels = { all:"item", password:"password", todo:"todo", bookmark:"bookmark", note:"note" };
    const hint = STATE.activeTags.length
      ? "No items match the selected tags."
      : "Your vault is empty — let's add something!";
    const actionLabel = STATE.tab === "all" ? "Add your first item" : `Add a ${labels[STATE.tab]||'item'}`;
    area.innerHTML = `<div class="empty">
      <div class="empty-ico">${icons[STATE.tab]||"🔐"}</div>
      <div class="empty-title">Nothing here yet</div>
      <div class="empty-sub">${hint}</div>
      ${!STATE.activeTags.length ? `<div class="empty-action" onclick="openAdd()">＋ ${actionLabel}</div>` : ''}
    </div>`;
    return;
  }
  
  STATE.currentFilteredList = list;
  STATE.renderLimit = 50;
  
  const itemsToRender = list.slice(0, STATE.renderLimit);
  area.innerHTML = itemsToRender.map(cardHTML).join("");
  area.scrollTop = 0;
}

function renderMoreListItems() {
  const area = $("list");
  if (!area) return;
  const itemsToRender = STATE.currentFilteredList.slice(0, STATE.renderLimit);
  area.innerHTML = itemsToRender.map(cardHTML).join("");
}

function renderAll() { renderList(); renderSelectedTags(); }

function cardHTML(item) {
  if (item.type === "todo") return todoCardHTML(item);
  const q = ($("q")?.value || "").toLowerCase().trim();
  const ico  = T_ICON[item.type]  || "📄";
  const cls  = T_CLASS[item.type] || "ip";
  const ccls = {password:"card-pw",bookmark:"card-bm",note:"card-nt"}[item.type] || "";
  const sub  = item.username || item.url || (item.note||"").slice(0,55) || "";
  const tags = (item.tags||[]).slice(0,2).map(t => `<span class="bpill bt">#${highlightMatch(t, q)}</span>`).join("");
  const fav  = item.fav ? `<span class="bpill bf">★</span>` : "";
  const pri  = item.priority === "high" ? `<span class="bpill bpp">⚡</span>` : item.priority === "medium" ? `<span class="bpill bpm">◉</span>` : item.priority === "low" ? `<span class="bpill bpl">▽</span>` : "";
  const exp  = STATE.expandedId === item.id;
  const id   = item.id;

  const ago = getItemAge(item);

  return `<div class="card ${ccls}${exp?" open":""}" id="card-${id}">
    <div class="card-top" onclick="toggleCard('${id}')">
      <div class="ci ${cls}">${ico}</div>
      <div class="cm">
        <div class="ct">${highlightMatch(item.title||"Untitled", q)}${ago ? `<span class="ct-ago">${ago}</span>` : ""}</div>
        <div class="cs">${highlightMatch(sub, q)}</div>
      </div>
      <div class="cbadges">${getFlagBadge(item)}${pri}${fav}${tags}</div>
      <div class="chev">⌄</div>
    </div>
    <div class="card-drawer">
      <div class="card-drawer-inner">
        <div class="card-detail">${detailHTML(item)}</div>
        <div class="card-actions">${actionsHTML(item)}</div>
      </div>
    </div>
  </div>`;
}

// ── Todo Card ──────────────────────────────────────────
function todoCardHTML(item) {
  const q = ($("q")?.value || "").toLowerCase().trim();
  const subs = item.subitems || [];
  const done = subs.filter(s => s.done).length;
  const total = subs.length;
  const colorClass = item.color ? " color-" + item.color : "";
  const colorHex = (TODO_COLORS.find(c => c.name === item.color) || TODO_COLORS[6]).hex;
  const tags = (item.tags||[]).slice(0,2).map(t => `<span class="bpill bt">#${highlightMatch(t, q)}</span>`).join("");
  const fav  = item.fav ? `<span class="bpill bf">★</span>` : "";
  const pri  = item.priority === "high" ? `<span class="bpill bpp">⚡</span>` : "";
  const exp  = STATE.expandedId === item.id;
  const id   = item.id;

  const pct = total ? Math.round(done/total*100) : 0;
  let tree = subs.map(s => {
    const d = s.done;
    return `<div class="todo-item sub">
      <div class="todo-check${d?" done":""}" onclick="event.stopPropagation();toggleTodoDone('${id}','${s.id}')">${d?"✓":""}</div>
      <div class="todo-text${d?" done-text":""}">${highlightMatch(s.text, q)}</div>
    </div>`;
  }).join("");

  const noteBlock = item.note ? `<div class="note-block">${highlightMatch(item.note, q).replace(/\n/g,"<br>")}</div>` : "";
  const tagBlock = (item.tags||[]).length ? `<div class="tag-chips">${item.tags.map(t=>`<span class="tc">#${highlightMatch(t, q)}</span>`).join("")}</div>` : "";

  const ago = getItemAge(item);

  return `<div class="card card-td todo-card${colorClass}${exp?" open":""}" id="card-${id}">
    <div class="card-top" onclick="toggleCard('${id}')">
      <div class="ci it">✅</div>
      <div class="cm">
        <div class="ct"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${colorHex};margin-right:6px;vertical-align:middle"></span>${highlightMatch(item.title||"Untitled", q)}${ago ? `<span class="ct-ago">${ago}</span>` : ""}</div>
        <div class="cs">${done} of ${total} completed</div>
      </div>
      <div class="cbadges">${getFlagBadge(item)}${pri}${fav}${tags}</div>
      <div class="chev">⌄</div>
    </div>
    <div class="card-drawer">
      <div class="card-drawer-inner">
        <div class="todo-detail">
          <div class="todo-progress">
            <div class="todo-prog-bar"><div class="todo-prog-fill" style="width:${pct}%"></div></div>
            <div class="todo-prog-label">${done}/${total} done</div>
          </div>
          <div class="todo-tree">${tree}</div>
          ${noteBlock}${tagBlock}
        </div>
        <div class="card-actions">
          <button class="cab ca-fav" onclick="toggleFav('${id}')">${item.fav ? SVGS.starFilled : SVGS.starEmpty}<span class="cab-lbl">Fav</span></button>
          <button class="cab ca-edit" onclick="openEdit('${id}')">${SVGS.edit}<span class="cab-lbl">Edit</span></button>
          <button class="cab ca-del" onclick="askDelete('${id}')">${SVGS.trash}<span class="cab-lbl">Delete</span></button>
        </div>
      </div>
    </div>
  </div>`;
}

async function toggleTodoDone(itemId, subId) {
  const item = STATE.items.find(i => i.id === itemId);
  if (!item || !item.subitems) return;
  const sub = item.subitems.find(s => s.id === subId);
  if (!sub) return;
  sub.done = !sub.done;
  await saveItem(item);
  renderList();
}

function getFlagBadge(item) {
  const fd = item.flagDate;
  if (!fd) return "";
  const days = Math.ceil((new Date(fd).getTime() - Date.now()) / 86400000);
  let cls, ico, label;
  if (days < 0)        { cls="expired"; ico="⛔";  label=`${Math.abs(days)}d ago`; }
  else if (days === 0) { cls="urgent";  ico="⚠️"; label="Today"; }
  else if (days <= 3)  { cls="urgent";  ico="⚠️"; label=`${days}d left`; }
  else if (days <= 14) { cls="soon";    ico="📅"; label=`${days}d left`; }
  else                 { cls="ok";      ico="📅"; label=new Date(fd).toLocaleDateString("en-US",{month:"short",day:"numeric"}); }
  return `<span class="flag-badge ${cls}">${ico} ${label}</span>`;
}

function detailHTML(item) {
  const q = ($("q")?.value || "").toLowerCase().trim();
  const id = item.id;
  let h = "";

  if (item.username) h += dRow("USER", highlightMatch(item.username, q), `copyVal('${id}','username')`);

  if (item.password) {
    const vis = STATE.pwVisible[id];
    h += `<div class="dr">
      <span class="dl">PASS</span>
      <span class="dv${vis?"":" masked"}" id="dv-pw-${id}">${vis ? esc(item.password) : "••••••••••"}</span>
      <span class="da" onclick="togglePwVis('${id}')" id="eye-${id}">${vis?"🙈":"👁"}</span>
      <span class="da" onclick="copyVal('${id}','password')" title="Copy">⎘</span>
    </div>`;
  }

  if (item.url)   h += dRow("URL",   `<span style="color:var(--blue)">${highlightMatch(item.url, q)}</span>`, `copyText('${esc(item.url)}')`);
  if (item.email) h += dRow("EMAIL", highlightMatch(item.email, q), `copyText('${esc(item.email)}')`);
  if (item.price) h += dRow("PRICE", highlightMatch(item.price, q));

  if (item.renewal) {
    const days = Math.ceil((new Date(item.renewal) - new Date()) / 86400000);
    const cls  = days < 0 ? "exp" : days < 30 ? "warn" : "ok";
    const ico  = days < 0 ? "❌"  : days < 30 ? "⚠️"   : "✅";
    const msg  = days < 0 ? `Expired ${Math.abs(days)}d ago` : days === 0 ? "Expires today" : `${days}d left`;
    h += `<div class="renewal ${cls}">${ico} Renews ${esc(item.renewal)} · ${msg}</div>`;
  }

  if (item.note) h += `<div class="note-block">${highlightMatch(item.note, q).replace(/\n/g,"<br>")}</div>`;

  if ((item.tags||[]).length) {
    h += `<div class="tag-chips">${item.tags.map(t=>`<span class="tc">#${highlightMatch(t, q)}</span>`).join("")}</div>`;
  }

  return `<div class="di">${h}</div>`;
}

function dRow(label, val, copyFn="") {
  return `<div class="dr">
    <span class="dl">${label}</span>
    <span class="dv">${val}</span>
    ${copyFn ? `<span class="da" onclick="${copyFn}" title="Copy">⎘</span>` : ""}
  </div>`;
}

function actionsHTML(item) {
  const id = item.id;
  let b = "";
  if (item.type==="password") {
    b += cab(SVGS.user, "User", "ca-copy", `copyVal('${id}','username')`);
    b += cab(SVGS.key, "Pass", "ca-copy", `copyVal('${id}','password')`);
  }
  if (item.url) b += cab(SVGS.link, "Open", "ca-link", `openLink('${id}')`);
  b += cab(item.fav ? SVGS.starFilled : SVGS.starEmpty, "Fav", "ca-fav", `toggleFav('${id}')`);
  b += cab(SVGS.edit, "Edit", "ca-edit", `openEdit('${id}')`);
  b += cab(SVGS.trash, "Delete", "ca-del", `askDelete('${id}')`);
  return b;
}

function cab(svg, label, cls, fn) {
  return `<button class="cab ${cls}" onclick="${fn}">${svg}<span class="cab-lbl">${label}</span></button>`;
}

function toggleCard(id) {
  // Hide any revealed passwords when switching cards
  STATE.pwVisible = {};
  const wasExpanded = STATE.expandedId === id;
  STATE.expandedId = wasExpanded ? null : id;
  
  // Directly manipulate DOM classes for buttery smooth opening/closing transitions
  const prevOpen = document.querySelector(".card.open");
  const newOpen = $("card-" + id);
  
  if (prevOpen) {
    prevOpen.classList.remove("open");
  }
  
  if (!wasExpanded && newOpen) {
    newOpen.classList.add("open");
    requestAnimationFrame(() => {
      newOpen.scrollIntoView({ behavior:"smooth", block:"nearest" });
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
  toast(`${field==="password"?"Password":"Username"} copied`);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied", "success");
    // Auto-clear clipboard after 30s for security
    if (_clipboardClearTimer) clearTimeout(_clipboardClearTimer);
    _clipboardClearTimer = setTimeout(async () => {
      try {
        await navigator.clipboard.writeText('');
        toast("Clipboard cleared for security 🔒", "info");
      } catch {}
    }, 30000);
  } catch { toast("Copy not available", "warn"); }
}
let _clipboardClearTimer = null;

function openLink(id) {
  const item = STATE.items.find(i => i.id === id);
  if (!item || !item.url) return;

  const extId = STATE.autofillExtensionId || LS.get("vault_autofill_extension_id");
  if (extId && typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
    // Attempt to send a message to the extension
    chrome.runtime.sendMessage(extId, { action: "ping" }, (response) => {
      if (chrome.runtime.lastError || !response || !response.success) {
        console.warn("[Vault] Extension not responding, opening tab directly.");
        window.open(item.url, "_blank", "noopener,noreferrer");
      } else {
        // Send login credentials and target URL to the extension helper
        chrome.runtime.sendMessage(extId, {
          action: "openAndAutofill",
          url: item.url,
          username: item.username || "",
          password: item.password || ""
        }, (res) => {
          if (chrome.runtime.lastError || !res || !res.success) {
            console.warn("[Vault] Extension open failed, opening tab directly.");
            window.open(item.url, "_blank", "noopener,noreferrer");
          } else {
            toast("Opening link with secure autofill...", "success");
          }
        });
      }
    });
  } else {
    // Direct open if no extension ID is configured or not supported
    window.open(item.url, "_blank", "noopener,noreferrer");
  }
}

async function toggleFav(id) {
  const item = STATE.items.find(i => i.id === id);
  if (!item) return;
  item.fav = !item.fav;
  await saveItem(item);
  renderList();
  // Star burst animation
  if (item.fav) {
    vibrate(30);
    const card = $("card-" + id);
    if (card) {
      card.classList.add("star-burst");
      setTimeout(() => card.classList.remove("star-burst"), 500);
    }
  }
  toast(item.fav ? "Added to favorites ★" : "Removed from favorites", item.fav ? "success" : "info");
}

// ══════════════════════════════════════════════════════════
//  ADD / EDIT FORM
// ══════════════════════════════════════════════════════════
function openAdd() {
  STATE.editId    = null;
  STATE.mTags     = [];
  STATE.focusedFormTagIndex = -1;
  STATE.focusedMTagIndex = -1;
  // Auto-detect type from current tab
  const tabType = ["password","bookmark","note","todo"].includes(STATE.tab) ? STATE.tab : "password";
  STATE.mType     = tabType;
  STATE.mPriority = "normal";
  STATE.mSubitems = [];
  STATE.mColor    = TODO_COLORS[Math.floor(Math.random() * TODO_COLORS.length)].name;
  STATE.mDashboard = false;
  $("add-title").textContent = "Add Item";
  buildForm(tabType, null);
  openOverlay("add-overlay");
}

function openEdit(id) {
  const item = STATE.items.find(i => i.id === id);
  if (!item) return;
  STATE.editId    = id;
  STATE.mTags     = [...(item.tags||[])];
  STATE.focusedFormTagIndex = -1;
  STATE.focusedMTagIndex = -1;
  STATE.mType     = item.type;
  STATE.mPriority = item.priority || "normal";
  STATE.mSubitems = (item.subitems||[]).map(s => ({...s}));
  STATE.mColor    = item.color || "purple";
  STATE.mDashboard = item.dashboard || false;
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
        <div class="tcard${type==="password"?" on":""}" onclick="switchType('password',this)"><span class="tci">🔑</span>Password</div>
        <div class="tcard${type==="bookmark"?" on":""}" onclick="switchType('bookmark',this)"><span class="tci">🔖</span>Bookmark</div>
        <div class="tcard${type==="note"?" on":""}" onclick="switchType('note',this)"><span class="tci">📝</span>Note</div>
        <div class="tcard${type==="todo"?" on":""}" onclick="switchType('todo',this)"><span class="tci">✅</span>Todo</div>
      </div>
    </div><div class="divider"></div>`;

  let fields = "";
  if (type === "password") {
    fields = `
      <div class="fg"><div class="fl">Title *</div><input class="fi" id="f-title" placeholder="Gmail, Netflix…" value="${esc(pre?.title||"")}" autocomplete="off"></div>
      <div class="fg"><div class="fl">Username / Email</div><input class="fi" id="f-username" placeholder="user@example.com" value="${esc(pre?.username||"")}" autocomplete="off"></div>
      <div class="fg"><div class="fl">Password</div>
        <div class="pw-wrap"><input class="fi mono" id="f-password" type="password" placeholder="••••••••" value="${esc(pre?.password||"")}" autocomplete="new-password" oninput="updateStrBar(this.value)">
        <span class="pweye" onclick="tpw('f-password')">👁</span></div>
        <div class="str-bar"><div class="str-fill" id="str-fill"></div></div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">
          <span class="gen-pill on" id="gp-upper" onclick="toggleGenPill(this,'upper')">A–Z</span>
          <span class="gen-pill on" id="gp-lower" onclick="toggleGenPill(this,'lower')">a–z</span>
          <span class="gen-pill on" id="gp-num" onclick="toggleGenPill(this,'num')">0–9</span>
          <span class="gen-pill on" id="gp-sym" onclick="toggleGenPill(this,'sym')">!@#</span>
        </div>
        <div style="display:flex;align-items:center;gap:10px;margin-top:6px">
          <span style="font-size:11px;color:var(--muted);white-space:nowrap">Length: <b id="gen-len-val">20</b></span>
          <input type="range" min="8" max="64" value="20" id="gen-len" oninput="$('gen-len-val').textContent=this.value" style="flex:1;accent-color:var(--ac)">
        </div>
        <div style="display:flex;gap:8px;margin-top:6px">
          <button type="button" class="btn primary" style="padding:8px 14px;font-size:12px;flex:1" onclick="genInlinePw()">🎲 Generate</button>
          <button type="button" class="btn ghost" style="padding:8px 14px;font-size:12px;flex:0 0 auto" onclick="copyInlinePw()">📋 Copy</button>
        </div>
      </div>
      <div class="fg"><div class="fl">Website URL</div><input class="fi" id="f-url" type="url" placeholder="https://" value="${esc(pre?.url||"")}"></div>
      <div class="fg"><div class="fl">Notes</div><textarea class="fi" id="f-note" placeholder="Optional notes…">${esc(pre?.note||"")}</textarea></div>`;
  } else if (type === "bookmark") {
    fields = `
      <div class="fg"><div class="fl">Title *</div><input class="fi" id="f-title" placeholder="Bookmark name" value="${esc(pre?.title||"")}"></div>
      <div class="fg"><div class="fl">URL *</div><input class="fi" id="f-url" type="url" placeholder="https://" value="${esc(pre?.url||"")}"></div>
      <div class="fg"><div class="fl">Description</div><textarea class="fi" id="f-note" placeholder="What's this link about?">${esc(pre?.note||"")}</textarea></div>`;
  } else if (type === "note") {
    fields = `
      <div class="fg"><div class="fl">Title *</div><input class="fi" id="f-title" placeholder="Note title" value="${esc(pre?.title||"")}"></div>
      <div class="fg"><div class="fl">Content</div><textarea class="fi" id="f-note" style="min-height:140px" placeholder="Write your note…">${esc(pre?.note||"")}</textarea></div>`;
  } else if (type === "todo") {
    const subItems = STATE.mSubitems.map((s,i) =>
      `<div class="subitem-row"><span class="sub-drag">⋮⋮</span><input class="sub-input" id="sub-${i}" value="${esc(s.text)}" placeholder="Sub-item…" oninput="STATE.mSubitems[${i}].text=this.value"><span class="sub-del" onclick="removeSubitem(${i})">✕</span></div>`
    ).join("");
    fields = `
      <div class="fg"><div class="fl">Title *</div><input class="fi" id="f-title" placeholder="Todo title" value="${esc(pre?.title||"")}" autocomplete="off"></div>
      <div class="fg"><div class="fl">Sub-items</div>
        <div id="subitems-list">${subItems}</div>
        <div class="add-sub-btn" onclick="addSubitem()">＋ Add Sub-item</div>
      </div>
      <div class="fg"><div class="fl">Notes</div><textarea class="fi" id="f-note" placeholder="Optional notes…">${esc(pre?.note||"")}</textarea></div>`;
  }

  const priorityBlock = `
    <div class="fg">
      <div class="fl">Priority</div>
      <div class="pri-row">
        <div class="pricard hi${STATE.mPriority==="high"?" on":""}" onclick="selectPri('high',this)"><span class="prico">⚡</span>High</div>
        <div class="pricard med${STATE.mPriority==="medium"?" on":""}" onclick="selectPri('medium',this)"><span class="prico">◉</span>Medium</div>
        <div class="pricard${STATE.mPriority==="normal"?" on":""}" onclick="selectPri('normal',this)"><span class="prico">○</span>Normal</div>
        <div class="pricard lo${STATE.mPriority==="low"?" on":""}" onclick="selectPri('low',this)"><span class="prico">▽</span>Low</div>
      </div>
    </div>`;

  const flagBlock = `
    <div class="fg">
      <div class="fl">Flag / Expires</div>
      <input class="fi" id="f-flagDate" type="date" value="${esc(pre?.flagDate||"")}" style="color-scheme:dark">
      <div style="font-size:11px;color:var(--faint);margin-top:3px">Optional — item will show an expiry countdown on cards</div>
    </div>`;

  const tagsBlock = `
    <div class="fg">
      <div class="fl">Tags</div>
      <div class="tag-add-row">
        <input class="fi" id="tag-inp" placeholder="Add a tag…" onkeydown="onFormTagKeyDown(event, this)" oninput="onFormTagInput(this)" autocomplete="off">
        <button class="tadd-btn" onclick="addTag()">+ Add</button>
      </div>
      <div id="form-tag-autocomplete" class="chips" style="display:none; margin-top:8px;"></div>
      <div class="chips" id="mchips" style="margin-top:8px">${renderChips()}</div>
    </div>`;

  const dashBlock = `
    <div class="fg">
      <div class="fl">Display on home</div>
      <div class="dash-toggle-row">
        <div class="dash-toggle-info">
          <span style="font-size:16px">📊</span>
          <span style="font-size:12px;color:var(--muted)">Show item on Home screen</span>
        </div>
        <div class="dash-switch${STATE.mDashboard ? ' on' : ''}" id="f-dash-switch" onclick="toggleDashSwitch()">
          <div class="dash-switch-knob"></div>
        </div>
      </div>
    </div>`;

  body.innerHTML = typeGrid + fields + priorityBlock + flagBlock + tagsBlock + dashBlock;
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

function toggleDashSwitch() {
  STATE.mDashboard = !STATE.mDashboard;
  const sw = document.getElementById("f-dash-switch");
  if (sw) sw.classList.toggle("on", STATE.mDashboard);
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

function updateStrBar(v) { updateStrength(); }

const _genOpts = { upper:true, lower:true, num:true, sym:true };

function toggleGenPill(el, key) {
  _genOpts[key] = !_genOpts[key];
  el.classList.toggle("on", _genOpts[key]);
}

function genInlinePw() {
  let chars = "";
  if (_genOpts.upper) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (_genOpts.lower) chars += "abcdefghijklmnopqrstuvwxyz";
  if (_genOpts.num)   chars += "0123456789";
  if (_genOpts.sym)   chars += "!@#$%^&*()-_=+[]{}|;:,.<>?";
  if (!chars) chars = "abcdefghijklmnopqrstuvwxyz";
  const len = +($("gen-len")?.value || 20);
  let pw = "";
  for (let i = 0; i < len; i++) pw += chars[Math.floor(Math.random() * chars.length)];
  const el = $("f-password");
  if (el) {
    el.value = pw;
    el.type = "text";
    updateStrength();
  }
  toast("Password generated", "success");
}

function copyInlinePw() {
  const pw = $("f-password")?.value || "";
  if (!pw) { toast("No password to copy", "warn"); return; }
  navigator.clipboard.writeText(pw).then(() => toast("Password copied", "success"));
}

function addTag() {
  const inp = $("tag-inp");
  const val = inp.value.trim().toLowerCase().replace(/\s+/g,"-");
  if (!val || STATE.mTags.includes(val)) { inp.value = ""; return; }
  STATE.mTags.push(val);
  inp.value = "";
  refreshChips();
  const dropdown = $("form-tag-autocomplete");
  if (dropdown) dropdown.style.display = "none";
}

function onFormTagInput(inp) {
  const q = inp.value.trim().toLowerCase();
  const dropdown = $("form-tag-autocomplete");
  if (!dropdown) return;
  if (!q) { 
    dropdown.style.display = "none"; 
    STATE.focusedFormTagIndex = -1;
    return; 
  }
  const matches = getAllTags()
    .filter(t => t.toLowerCase().includes(q) && !STATE.mTags.includes(t))
    .slice(0, 10);
  if (!matches.length) { 
    dropdown.style.display = "none"; 
    STATE.focusedFormTagIndex = -1;
    return; 
  }
  dropdown.style.display = "flex";
  dropdown.innerHTML = matches.map((t, idx) => {
    const activeClass = idx === STATE.focusedFormTagIndex ? " active-highlight" : "";
    return `<span class="suggest-tag-pill${activeClass}" onclick="selectFormTag('${esc(t)}')" id="form-suggest-item-${idx}"><span class="pill-hash">#</span>${esc(t)}</span>`;
  }).join("");
}

function selectFormTag(tag) {
  if (!STATE.mTags.includes(tag)) {
    STATE.mTags.push(tag);
    refreshChips();
  }
  const inp = $("tag-inp");
  if (inp) inp.value = "";
  const dropdown = $("form-tag-autocomplete");
  if (dropdown) dropdown.style.display = "none";
  STATE.focusedFormTagIndex = -1;
}

function updateFormTagHighlight(matchesLength) {
  for (let idx = 0; idx < matchesLength; idx++) {
    const el = $(`form-suggest-item-${idx}`);
    if (el) {
      if (idx === STATE.focusedFormTagIndex) {
        el.classList.add("active-highlight");
        el.scrollIntoView({ block: "nearest" });
      } else {
        el.classList.remove("active-highlight");
      }
    }
  }
}

function onFormTagKeyDown(e, inp) {
  const dropdown = $("form-tag-autocomplete");
  const matches = !dropdown || dropdown.style.display === "none" ? [] : getAllTags()
    .filter(t => t.toLowerCase().includes(inp.value.trim().toLowerCase()) && !STATE.mTags.includes(t))
    .slice(0, 10);

  if (matches.length > 0) {
    if (e.key === "ArrowRight" || e.key === "ArrowDown") {
      e.preventDefault();
      STATE.focusedFormTagIndex = (STATE.focusedFormTagIndex + 1) % matches.length;
      updateFormTagHighlight(matches.length);
      return;
    } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
      e.preventDefault();
      STATE.focusedFormTagIndex = (STATE.focusedFormTagIndex - 1 + matches.length) % matches.length;
      updateFormTagHighlight(matches.length);
      return;
    } else if (e.key === "Enter" || e.key === "Tab" || e.key === ",") {
      if (STATE.focusedFormTagIndex >= 0 && STATE.focusedFormTagIndex < matches.length) {
        e.preventDefault();
        selectFormTag(matches[STATE.focusedFormTagIndex]);
        return;
      }
    } else if (e.key === "Escape") {
      e.preventDefault();
      dropdown.style.display = "none";
      STATE.focusedFormTagIndex = -1;
      return;
    }
  }

  if (inp.selectionStart === 0 && inp.selectionEnd === 0) {
    if (e.key === "Backspace") {
      if (STATE.mTags.length > 0) {
        e.preventDefault();
        if (STATE.focusedMTagIndex === -1) {
          STATE.focusedMTagIndex = STATE.mTags.length - 1;
          refreshChips();
        } else {
          const tagToRemove = STATE.mTags[STATE.focusedMTagIndex];
          STATE.mTags = STATE.mTags.filter(t => t !== tagToRemove);
          const newLength = STATE.mTags.length;
          if (newLength === 0) {
            STATE.focusedMTagIndex = -1;
          } else {
            STATE.focusedMTagIndex = Math.min(newLength - 1, STATE.focusedMTagIndex);
          }
          refreshChips();
        }
        return;
      }
    } else if (e.key === "ArrowLeft") {
      if (STATE.mTags.length > 0) {
        e.preventDefault();
        if (STATE.focusedMTagIndex === -1) {
          STATE.focusedMTagIndex = STATE.mTags.length - 1;
        } else {
          STATE.focusedMTagIndex = Math.max(0, STATE.focusedMTagIndex - 1);
        }
        refreshChips();
        return;
      }
    } else if (e.key === "ArrowRight") {
      if (STATE.focusedMTagIndex !== -1) {
        e.preventDefault();
        STATE.focusedMTagIndex++;
        if (STATE.focusedMTagIndex >= STATE.mTags.length) {
          STATE.focusedMTagIndex = -1;
        }
        refreshChips();
        return;
      }
    }
  }

  if (e.key !== "ArrowLeft" && e.key !== "ArrowRight" && e.key !== "Backspace") {
    if (STATE.focusedMTagIndex !== -1) {
      STATE.focusedMTagIndex = -1;
      refreshChips();
    }
  }

  if (e.key === "Enter" || e.key === "Tab" || e.key === ",") {
    const val = inp.value.trim().toLowerCase().replace(/\s+/g,"-");
    if (val) {
      e.preventDefault();
      let tagText = val.startsWith("#") ? val.slice(1) : val;
      if (tagText.endsWith(",")) tagText = tagText.slice(0, -1);
      tagText = tagText.trim();
      if (tagText && !STATE.mTags.includes(tagText)) {
        STATE.mTags.push(tagText);
        refreshChips();
      }
      inp.value = "";
      if (dropdown) dropdown.style.display = "none";
      STATE.focusedFormTagIndex = -1;
    }
  }
}
function removeTag(t) { STATE.mTags = STATE.mTags.filter(v => v !== t); refreshChips(); }
function renderChips() {
  return STATE.mTags.map((t, idx) => {
    const isFocused = idx === STATE.focusedMTagIndex;
    const focusClass = isFocused ? " focused" : "";
    return `<div class="chip${focusClass}">#${esc(t)}<span class="chip-x" onclick="removeTag('${esc(t)}')">✕</span></div>`;
  }).join("");
}
function refreshChips() { const el = $("mchips"); if (el) el.innerHTML = renderChips(); }

function fv(id) { return ($(id)?.value || "").trim(); }

async function submitItem() {
  const title = fv("f-title");
  if (!title) { toast("Title is required"); return; }
  const existing = STATE.editId ? STATE.items.find(i => i.id === STATE.editId) : null;
  const itemType = existing?.type || STATE.mType;
  const item = {
    id       : STATE.editId || genId(),
    type     : itemType,
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
    dashboard: STATE.mDashboard || false,
  };
  // Todo-specific fields
  if (itemType === "todo") {
    item.color = STATE.mColor;
    item.subitems = STATE.mSubitems.filter(s => s.text.trim()).map(s => ({
      id: s.id || genId(),
      text: s.text.trim(),
      done: s.done || false,
    }));
  }
  await saveItem(item);
  closeOverlay("add-overlay");
  renderAll(); updateStats();
  toast(STATE.editId ? "Item updated" : "Item added", "success");
}

function selectColor(name) {
  STATE.mColor = name;
  document.querySelectorAll(".color-dot").forEach(d => d.classList.remove("on"));
  event.target.classList.add("on");
}

function addSubitem() {
  STATE.mSubitems.push({ id:genId(), text:"", done:false });
  refreshSubitems();
  // Focus the new input
  setTimeout(() => {
    const inp = $("sub-" + (STATE.mSubitems.length-1));
    if (inp) inp.focus();
  }, 50);
}

function removeSubitem(idx) {
  STATE.mSubitems.splice(idx, 1);
  refreshSubitems();
}

function refreshSubitems() {
  const el = $("subitems-list");
  if (!el) return;
  el.innerHTML = STATE.mSubitems.map((s,i) =>
    `<div class="subitem-row"><span class="sub-drag">⋮⋮</span><input class="sub-input" id="sub-${i}" value="${esc(s.text)}" placeholder="Sub-item…" oninput="STATE.mSubitems[${i}].text=this.value"><span class="sub-del" onclick="removeSubitem(${i})">✕</span></div>`
  ).join("");
}

// ══════════════════════════════════════════════════════════
//  DELETE
// ══════════════════════════════════════════════════════════
function askDelete(id) {
  const item = STATE.items.find(i => i.id === id);
  if (!item) return;
  $("confirm-title").textContent  = "Delete Item";
  $("confirm-msg").textContent    = `Delete "${item.title}"? This cannot be undone.`;
  $("confirm-ok").textContent     = "Delete";
  $("confirm-ok").onclick = async () => {
    STATE.expandedId = null;
    closeOverlay("confirm-overlay");
    toast("Deleted", "info");
    await removeItem(id);
  };
  openOverlay("confirm-overlay");
}

// ══════════════════════════════════════════════════════════
//  IMPORT / EXPORT
// ══════════════════════════════════════════════════════════
async function exportJSON() {
  const encrypted = await Crypto.encrypt(STATE.items, STATE.masterKey);
  const payload   = JSON.stringify({ version:2, app:"vault-pwa", exported:new Date().toISOString(), vault:encrypted });
  const dateStr   = new Date().toISOString().slice(0,10);
  dl(`vault-backup-${dateStr}.enc.json`, payload, "application/json");
  toast("Vault exported", "success");
}

function exportCSV() {
  const rows = [["ID","Type","Title","Username","URL","Email","Price","Renewal","Tags","Note"]];
  STATE.items.forEach(i => rows.push([
    i.id, i.type, i.title||"", i.username||"", i.url||"",
    i.email||"", i.price||"", i.renewal||"", (i.tags||[]).join(";"), i.note||"",
  ]));
  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(",")).join("\n");
  dl("vault-export.csv", csv, "text/csv");
  toast("CSV exported (passwords excluded for safety)", "success");
}

function dl(name, content, mime) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([content], { type:mime }));
  a.download = name; a.click();
}

function parseCSV(text) {
  const lines = [];
  let row = [""];
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const next = text[i+1];
    if (c === '"') {
      if (inQuotes && next === '"') {
        row[row.length - 1] += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (c === ',' && !inQuotes) {
      row.push("");
    } else if ((c === '\r' || c === '\n') && !inQuotes) {
      if (c === '\r' && next === '\n') i++;
      lines.push(row);
      row = [""];
    } else {
      row[row.length - 1] += c;
    }
  }
  if (row.length > 1 || row[0] !== "") {
    lines.push(row);
  }
  return lines;
}

function csvToItems(csvText) {
  const rows = parseCSV(csvText);
  if (rows.length < 2) return [];
  const header = rows[0].map(h => h.trim().toLowerCase());
  const items = [];
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    if (row.length < header.length) continue;
    const item = {
      id: genId(),
      type: "password",
      fav: false,
      created: Date.now(),
      tags: [],
    };
    header.forEach((colName, idx) => {
      const val = row[idx] ? row[idx].trim() : "";
      if (colName === "id" && val) item.id = val;
      else if (colName === "type" && val) item.type = val;
      else if (colName === "tags") {
        item.tags = val ? val.split(";").map(t => t.trim()).filter(Boolean) : [];
      } else if (colName === "fav") {
        item.fav = val === "true" || val === "1";
      } else if (colName === "created") {
        item.created = parseInt(val) || Date.now();
      } else if (colName === "priority") {
        item.priority = val || "normal";
      } else if (colName === "dashboard") {
        item.dashboard = val === "true" || val === "1";
      } else if (colName === "color") {
        item.color = val;
      } else {
        item[colName] = val;
      }
    });
    items.push(item);
  }
  return items;
}

function pickImport() { $("imp-file").click(); }

async function doImport(e) {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    let imported = [];
    
    if (file.name.endsWith(".csv")) {
      imported = csvToItems(text);
    } else {
      let payload;
      try {
        payload = JSON.parse(text);
      } catch (jsonErr) {
        // Fallback: try parsing as CSV in case CSV had incorrect extension/mime or formatting
        try {
          imported = csvToItems(text);
          if (imported.length === 0) throw jsonErr;
        } catch {
          throw jsonErr;
        }
      }
      
      if (imported.length === 0 && payload) {
        if (payload.vault) {
          if (typeof payload.vault === "string") {
            // Encrypted JSON backup
            imported = await Crypto.decrypt(payload.vault, STATE.masterKey);
          } else if (Array.isArray(payload.vault)) {
            // Unencrypted JSON backup under "vault"
            imported = payload.vault;
          }
        } else if (Array.isArray(payload)) {
          // Direct array of items
          imported = payload;
        } else if (payload.items && Array.isArray(payload.items)) {
          // Object containing items array
          imported = payload.items;
        } else {
          throw new Error("Invalid JSON structure");
        }
      }
    }

    if (!Array.isArray(imported)) {
      throw new Error("Parsed data is not an array of items");
    }

    let added = 0;
    for (const item of imported) {
      if (!item.id) item.id = genId();
      if (!item.type) item.type = "password";
      if (!STATE.items.find(i => i.id === item.id)) {
        STATE.items.push(item);
        added++;
      }
    }
    await persistItems();
    if (STATE.drive.token) triggerSync();
    renderAll(); updateStats();
    toast(`Imported ${added} items`, "success");
  } catch (err) {
    toast("Import failed: " + err.message, "error");
  }
}

// ══════════════════════════════════════════════════════════
//  SETTINGS
// ══════════════════════════════════════════════════════════
function updateStats() {
  const grid = $("stat-grid");
  if (!grid) return;
  const c = { password:0, todo:0, bookmark:0, note:0 };
  const activeItems = STATE.items.filter(i => !i.deleted);
  activeItems.forEach(i => { if (c[i.type] !== undefined) c[i.type]++; });
  const favCount = activeItems.filter(i => i.fav).length;
  const data = [
    [activeItems.length, "Total Items", "🗄️"],
    [favCount,           "Favorites",   "★"],
    [c.password,         "Passwords",   "🔑"],
    [c.todo,             "Todos",       "✅"],
    [c.bookmark,         "Bookmarks",   "🔖"],
    [c.note,             "Notes",       "📝"],
  ];
  grid.innerHTML = data.map(([n,l,i]) =>
    `<div class="stat-box"><div class="stat-n" data-target="${n}">0</div><div class="stat-l">${i} ${l}</div></div>`
  ).join("");
  // Animate counters
  requestAnimationFrame(() => {
    grid.querySelectorAll('.stat-n[data-target]').forEach(el => {
      animateCounter(el, parseInt(el.dataset.target));
    });
  });
}

async function changeMasterPw() {
  const nw = $("new-pw").value.trim();
  if (nw.length < 4) { toast("Min 4 characters"); return; }
  STATE.masterKey = nw;
  await persistItems();
  LS.set("vault_hash", await Crypto.hashPassword(nw));
  $("new-pw").value = "";
  if (STATE.drive.token) triggerSync();
  toast("Master password updated", "success");
}

function clearAll() {
  $("confirm-title").textContent = "Wipe All Data";
  $("confirm-msg").textContent   = "This permanently deletes your ENTIRE vault — all passwords, bookmarks, and notes. This CANNOT be undone.";
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
  toast("Sort updated", "info");
}

// ══════════════════════════════════════════════════════════
//  AUTO-LOCK TIMER
// ══════════════════════════════════════════════════════════
let _autoLockTimer = null;
let _autoLockStart = 0;
let _autoLockDuration = 0;
let _autoLockRAF = null;

function startAutoLock() {
  stopAutoLock();
  const mins = STATE.autoLockMin;
  if (!mins || mins <= 0) {
    const bar = $("autolock-bar");
    if (bar) bar.style.width = '0%';
    return;
  }
  _autoLockDuration = mins * 60 * 1000;
  _autoLockStart = Date.now();
  // Listen for activity
  ['click','keydown','touchstart','mousemove','scroll'].forEach(e =>
    document.addEventListener(e, resetAutoLock, { passive: true })
  );
  updateAutoLockBar();
}

function stopAutoLock() {
  if (_autoLockTimer) clearTimeout(_autoLockTimer);
  if (_autoLockRAF) cancelAnimationFrame(_autoLockRAF);
  _autoLockTimer = null;
  _autoLockRAF = null;
  ['click','keydown','touchstart','mousemove','scroll'].forEach(e =>
    document.removeEventListener(e, resetAutoLock)
  );
  const bar = $("autolock-bar");
  if (bar) { bar.style.width = '0%'; bar.classList.remove('urgent'); }
}

function resetAutoLock() {
  if (!STATE.masterKey) return;
  _autoLockStart = Date.now();
  LS.set("vault_last_activity", _autoLockStart.toString());
  const bar = $("autolock-bar");
  if (bar) bar.classList.remove('urgent');
}

function updateAutoLockBar() {
  if (!STATE.masterKey || !_autoLockDuration) return;
  const elapsed = Date.now() - _autoLockStart;
  const remaining = _autoLockDuration - elapsed;
  const pct = Math.max(0, (remaining / _autoLockDuration) * 100);
  const bar = $("autolock-bar");
  if (bar) {
    bar.style.width = pct + '%';
    // Urgent state when < 30 seconds left
    if (remaining < 30000 && remaining > 0) {
      bar.classList.add('urgent');
    }
  }
  if (remaining <= 0) {
    lockVault();
    toast("Vault locked — inactivity timeout 🔒", "warn");
    return;
  }
  _autoLockRAF = requestAnimationFrame(updateAutoLockBar);
}

function setAutoLock(mins, el) {
  STATE.autoLockMin = mins;
  LS.set("vault_autolock", mins);
  document.querySelectorAll(".al-pill").forEach(c => c.classList.remove("on"));
  if (el) el.classList.add("on");
  // Restart timer with new duration
  if (STATE.masterKey) startAutoLock();
  toast(mins ? `Auto-lock: ${mins} min` : "Auto-lock disabled", "info");
}

function initAutoLockUI() {
  const saved = LS.get("vault_autolock");
  if (saved !== null && saved !== undefined) STATE.autoLockMin = saved;
  const pills = document.querySelectorAll(".al-pill");
  pills.forEach(p => {
    p.classList.remove("on");
    const val = parseInt(p.textContent);
    if (isNaN(val) && STATE.autoLockMin === 0) p.classList.add("on");
    else if (val === STATE.autoLockMin) p.classList.add("on");
  });
}

function initAutofillUI() {
  const inp = $("ext-id-input");
  if (inp) {
    inp.value = STATE.autofillExtensionId || "";
  }
}

function saveExtensionId(val) {
  STATE.autofillExtensionId = val.trim();
  LS.set("vault_autofill_extension_id", STATE.autofillExtensionId);
  syncWithExtension(false);
}

function syncWithExtension(clear = false) {
  const extId = STATE.autofillExtensionId || LS.get("vault_autofill_extension_id");
  if (!extId || typeof chrome === "undefined" || !chrome.runtime || !chrome.runtime.sendMessage) {
    return;
  }
  if (clear) {
    chrome.runtime.sendMessage(extId, { action: "clearVault" }, () => {
      if (chrome.runtime.lastError) { /* ignore */ }
    });
  } else {
    const credentials = (STATE.items || [])
      .filter(item => !item.deleted && item.type === "password" && item.password)
      .map(item => ({
        id: item.id,
        title: item.title,
        username: item.username || "",
        password: item.password || "",
        url: item.url || ""
      }));
    chrome.runtime.sendMessage(extId, { action: "syncVault", items: credentials }, (response) => {
      if (chrome.runtime.lastError) {
        console.warn("[Vault] Extension sync failed:", chrome.runtime.lastError.message);
      } else {
        console.log("[Vault] Credentials synced with extension successfully.");
      }
    });
  }
}


// ══════════════════════════════════════════════════════════
//  FAB PULSE
// ══════════════════════════════════════════════════════════
function updateFabPulse() {
  const fab = $("fab");
  if (!fab) return;
  fab.classList.toggle("pulse-hint", STATE.items.length === 0);
}

// ══════════════════════════════════════════════════════════
//  DASHBOARD — opt-in via item.dashboard flag
// ══════════════════════════════════════════════════════════
let _dashExpanded = null;

function todayKey() {
  const d = new Date();
  return `vault_dash_${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}
function getDashState() { return LS.get(todayKey()) || { completed: [], order: [] }; }
function saveDashState(s) { LS.set(todayKey(), s); }

function getDashItems() {
  return STATE.items.filter(item => !item.deleted && item.dashboard === true);
}

function renderDashboard() {
  const el = $("dashboard");
  if (!el) return;

  const allDash = getDashItems();
  const ds = getDashState();
  const completedIds = new Set(ds.completed);
  let pending = allDash.filter(i => !completedIds.has(i.id));
  const completed = allDash.filter(i => completedIds.has(i.id));

  // Apply custom order
  if (ds.order.length) {
    const om = {}; ds.order.forEach((id,i) => om[id] = i);
    pending.sort((a,b) => (om[a.id] ?? 9999) - (om[b.id] ?? 9999));
  }
  // Persist order
  const curOrd = pending.map(i => i.id);
  if (JSON.stringify(curOrd) !== JSON.stringify(ds.order)) { ds.order = curOrd; saveDashState(ds); }

  const total = allDash.length, doneN = completed.length, pendN = pending.length;
  const pct = total ? Math.round(doneN / total * 100) : 0;
  const dateStr = new Date().toLocaleDateString("en-US",{weekday:"short",month:"short",day:"numeric"});
  const r = 23, circ = 2*Math.PI*r, offset = circ - (pct/100)*circ;

  let html = `<div class="dash-header">
    <div class="dash-ring">
      <svg width="56" height="56" viewBox="0 0 56 56">
        <circle class="dash-ring-bg" cx="28" cy="28" r="${r}" fill="none" stroke-width="5"/>
        <circle class="dash-ring-fg" cx="28" cy="28" r="${r}" fill="none" stroke-width="5"
          stroke-dasharray="${circ}" stroke-dashoffset="${offset}"/>
      </svg>
      <div class="dash-ring-txt">${pct}%</div>
    </div>
    <div class="dash-info">
      <div class="dash-title">Home</div>
      <div class="dash-date">${dateStr}</div>
      <div class="dash-pills">
        <span class="dash-pill pending">${pendN} Pending</span>
        <span class="dash-pill done">${doneN} Done</span>
      </div>
    </div>
  </div>`;

  const cloudItems = STATE.items.filter(item => !item.deleted && item.dashboard);
  if (cloudItems.length > 0) {
    const colors = ["#4ade80", "#f87171", "#fbbf24", "#60a5fa", "#22d3ee", "#a855f7", "#e879f9", "#34d399", "#f472b6", "#fb923c"];
    let cloudHtml = `<div class="kw-cloud-container" style="margin:20px 24px; padding:24px; background:rgba(var(--s1-rgb), 0.55); border-radius:24px; text-align:center;">
      <div style="display:flex; flex-wrap:wrap; gap:12px; justify-content:center; align-items:center;">`;
    cloudItems.forEach(item => {
       let size = 18;
       if (item.priority === "high") size = 32;
       else if (item.priority === "medium") size = 24;
       else if (item.priority === "low") size = 14;
       const randColor = colors[(item.title.length * 7) % colors.length];
       const pseudoRand = (item.title.length * 13) % 10;
       cloudHtml += `<span class="cloud-kw" style="font-size: ${size}px; color:${randColor}; animation-delay:-${pseudoRand}s;" onclick="event.stopPropagation(); dashToggleExpand('${item.id}')">${esc(item.title)}</span>`;
    });
    cloudHtml += `</div></div>`;
    html += cloudHtml;
  }

  if (!allDash.length) {
    html += `<div class="dash-empty">
      <div class="dash-empty-ico">📋</div>
      <div class="dash-empty-msg">No items on your Home page yet.<br>Toggle "Display on home" when creating items.</div>
    </div>`;
    el.innerHTML = html; return;
  }

  if (pending.length) {
    html += `<div class="dash-sec-label">⏳ Pending · ${pendN}</div>`;
    pending.forEach((item,idx) => { html += dashCardHTML(item,false,idx,pending.length); });
  }
  if (completed.length) {
    html += `<div class="dash-sec-label">✅ Completed · ${doneN}</div>`;
    completed.forEach(item => { html += dashCardHTML(item,true,-1,-1); });
  }
  el.innerHTML = html;
}

function dashCardHTML(item, isDone, idx, total) {
  const TSUB = {password:"🔑",bookmark:"🔖",note:"📝",todo:"✅"};
  const DCLS = {password:"dc-pw",bookmark:"dc-bm",note:"dc-nt",todo:"dc-td"};
  const sub = item.type==="todo"
    ? `${(item.subitems||[]).filter(s=>s.done).length}/${(item.subitems||[]).length} sub-items`
    : (item.username||item.url||(item.note||"").slice(0,40)||"");
  const ago = getItemAge(item);
  const isExp = _dashExpanded === item.id;

  let arrows = "";
  if (!isDone && total > 1) {
    const upSvg = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M18 15l-6-6-6 6"/></svg>`;
    const dnSvg = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>`;
    arrows = `<div class="dcard-arrows">
      <button class="darr" onclick="event.stopPropagation();dashMoveUp('${item.id}')"${idx===0?' style="visibility:hidden"':''}>${upSvg}</button>
      <button class="darr" onclick="event.stopPropagation();dashMoveDown('${item.id}')"${idx===total-1?' style="visibility:hidden"':''}>${dnSvg}</button>
    </div>`;
  }

  return `<div class="dcard ${DCLS[item.type]||""}${isDone?" done-card":""}${isExp?" open":""}" id="dc-${item.id}">
    <div class="dcard-top" onclick="dashToggleExpand('${item.id}')">
      <div class="dcheck${isDone?" checked":""}" onclick="event.stopPropagation();dashToggleDone('${item.id}')">${isDone?"✓":""}</div>
      <div class="dcard-mid">
        <div class="dcard-title">${TSUB[item.type]||"📄"} ${esc(item.title||"Untitled")}${ago?` <span class="ct-ago">${ago}</span>`:""}</div>
        <div class="dcard-sub">${esc(sub)}</div>
      </div>
      ${arrows}
      <div class="dcard-expand">⌄</div>
    </div>
    ${isExp?`<div class="dcard-detail">${dashDetailHTML(item)}</div>`:""}
  </div>`;
}

function dashDetailHTML(item) {
  let h = "";
  if (item.username) h += `<div class="dd-row"><span class="dd-label">User</span><span class="dd-val">${esc(item.username)}</span></div>`;
  if (item.password) h += `<div class="dd-row"><span class="dd-label">Pass</span><span class="dd-val" style="color:var(--faint);letter-spacing:3px">••••••••</span></div>`;
  if (item.url) h += `<div class="dd-row"><span class="dd-label">URL</span><span class="dd-val" style="color:var(--blue)">${esc(item.url)}</span></div>`;
  if (item.email) h += `<div class="dd-row"><span class="dd-label">Email</span><span class="dd-val">${esc(item.email)}</span></div>`;

  if (item.type==="todo" && Array.isArray(item.subitems) && item.subitems.length) {
    h += `<div style="margin-bottom:6px">`;
    item.subitems.forEach(s => {
      h += `<div style="display:flex;align-items:center;gap:8px;padding:4px 0;font-size:12px;cursor:pointer" onclick="event.stopPropagation();toggleTodoDone('${item.id}','${s.id}');setTimeout(renderDashboard,100)">
        <span style="color:${s.done?'var(--green)':'var(--faint)'}">${s.done?'✓':'○'}</span>
        <span style="${s.done?'text-decoration:line-through;color:var(--faint)':'color:var(--tx)'}">${esc(s.text)}</span>
      </div>`;
    });
    h += `</div>`;
  }

  if (item.note) h += `<div class="dd-note">${esc(item.note).replace(/\n/g,"<br>")}</div>`;
  if ((item.tags||[]).length) h += `<div class="dd-tags">${item.tags.map(t=>`<span class="dd-tag">#${esc(t)}</span>`).join("")}</div>`;
  if (item.flagDate) {
    const days = Math.ceil((new Date(item.flagDate).getTime()-Date.now())/86400000);
    h += `<div class="dd-meta"><span>📅 ${item.flagDate} · ${days<0?Math.abs(days)+'d overdue':days===0?'Due today':days+'d left'}</span></div>`;
  }

  // Action buttons
  h += `<div class="dd-actions">
    <button class="dd-act" onclick="event.stopPropagation();openEdit('${item.id}')" style="color:var(--ac2)">✏️ Edit</button>
    <button class="dd-act" onclick="event.stopPropagation();askDelete('${item.id}')" style="color:var(--red)">🗑 Delete</button>
  </div>`;

  return h;
}

function dashToggleDone(id) {
  const ds = getDashState();
  const idx = ds.completed.indexOf(id);
  if (idx >= 0) { ds.completed.splice(idx,1); ds.order.push(id); }
  else { ds.completed.push(id); ds.order = ds.order.filter(o=>o!==id); }
  saveDashState(ds); vibrate(25); renderDashboard();
}

function dashMoveUp(id) {
  const ds = getDashState();
  if (!ds.order.length) ds.order = getDashItems().filter(i=>!ds.completed.includes(i.id)).map(i=>i.id);
  const idx = ds.order.indexOf(id);
  if (idx <= 0) return;
  [ds.order[idx],ds.order[idx-1]] = [ds.order[idx-1],ds.order[idx]];
  saveDashState(ds); renderDashboard();
  requestAnimationFrame(()=>$("dc-"+id)?.scrollIntoView({behavior:"smooth",block:"nearest"}));
}

function dashMoveDown(id) {
  const ds = getDashState();
  if (!ds.order.length) ds.order = getDashItems().filter(i=>!ds.completed.includes(i.id)).map(i=>i.id);
  const idx = ds.order.indexOf(id);
  if (idx < 0 || idx >= ds.order.length-1) return;
  [ds.order[idx],ds.order[idx+1]] = [ds.order[idx+1],ds.order[idx]];
  saveDashState(ds); renderDashboard();
  requestAnimationFrame(()=>$("dc-"+id)?.scrollIntoView({behavior:"smooth",block:"nearest"}));
}

function dashToggleExpand(id) {
  _dashExpanded = _dashExpanded===id ? null : id;
  renderDashboard();
  if (_dashExpanded) requestAnimationFrame(()=>$("dc-"+id)?.scrollIntoView({behavior:"smooth",block:"nearest"}));
}

// ══════════════════════════════════════════════════════════
//  ANIMATED STAT COUNTERS
// ══════════════════════════════════════════════════════════
function animateCounter(el, target) {
  const duration = 600;
  const start = performance.now();
  const initial = 0;
  const step = (now) => {
    const progress = Math.min((now - start) / duration, 1);
    // Ease out cubic
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(initial + (target - initial) * eased);
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}



// ══════════════════════════════════════════════════════════
//  PAGE NAV
// ══════════════════════════════════════════════════════════
function showPage(p) {
  const isDash = STATE.tab === "dash";
  const statusbar = $("statusbar"); if (statusbar) statusbar.style.display = "";
  if ($("search-row")) $("search-row").style.display = !isDash ? "" : "none";
  if ($("tag-filter-row")) $("tag-filter-row").style.display = !isDash ? "flex" : "none";
  if ($("list")) $("list").style.display = !isDash ? "flex" : "none";
  if ($("dashboard")) $("dashboard").style.display = isDash ? "flex" : "none";
  $("drive-banner").style.display = (!STATE.drive.token && !LS.get("drive_banner_dismissed")) ? "flex" : "none";
  $("fab").style.display = "flex";
  if (isDash) renderDashboard();
}

function toggleSettings(show) {
  const s = $("settings");
  const b = $("settings-backdrop");
  if (show) {
    if (s) s.classList.add("show");
    if (b) b.classList.add("show");
    updateStats();
    renderDrivePanel();
    renderSQSettings();
    renderBioSettings();
    renderThemeUI();
  } else {
    if (s) s.classList.remove("show");
    if (b) b.classList.remove("show");
  }
}

function dismissBanner() {
  $("drive-banner").classList.remove("show");
  LS.set("drive_banner_dismissed","1");
}

// ══════════════════════════════════════════════════════════
//  OVERLAYS
// ══════════════════════════════════════════════════════════
function openOverlay(id)  { $(id).classList.add("open"); }
function closeOverlay(id) { $(id).classList.remove("open"); }
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".overlay").forEach(o => {
    o.addEventListener("click", e => { if (e.target === o) o.classList.remove("open"); });
  });
});


// ══════════════════════════════════════════════════════════
//  TOAST — Premium with context icons & progress bar
// ══════════════════════════════════════════════════════════
let _tt;
function toast(msg, type = "info") {
  const t = $("toast");
  if (!t) return;

  // Modern vector SVG icons for context-based status badges
  const icons = {
    success: `<svg class="toast-svg-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
    error: `<svg class="toast-svg-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
    warn: `<svg class="toast-svg-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    info: `<svg class="toast-svg-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`
  };
  
  const titleMap = {
    success: "Success",
    error: "Error",
    warn: "Warning",
    info: "Info"
  };

  const title = titleMap[type] || "Info";
  const svg = icons[type] || "";

  t.innerHTML = `
    <div class="toast-icon-wrapper toast-icon-${type}">
      ${svg}
    </div>
    <div class="toast-content">
      <div class="toast-title toast-title-${type}">${title}</div>
      <div class="toast-msg">${msg}</div>
    </div>
    <div id="toast-progress" style="width: 100%;"></div>
  `;

  // Apply visual trigger class
  t.className = `show toast-${type}`;

  const progressEl = $("toast-progress");
  if (progressEl) {
    progressEl.style.transition = 'none';
    progressEl.style.width = '100%';
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        progressEl.style.transition = 'width 2.6s linear';
        progressEl.style.width = '0%';
      });
    });
  }

  clearTimeout(_tt);
  _tt = setTimeout(() => {
    t.className = '';
  }, 2600);
}

// ══════════════════════════════════════════════════════════
//  TAG AUTOCOMPLETE (inline)
// ══════════════════════════════════════════════════════════
function removeActiveTag(tag) {
  STATE.activeTags = STATE.activeTags.filter(t => t !== tag);
  STATE.focusedActiveTagIndex = -1;
  renderSelectedTags();
  renderList();
}

function removeActiveType() {
  STATE.typeFilter = null;
  STATE.focusedActiveTagIndex = -1;
  renderSelectedTags();
  renderList();
}

function clearAllTags() {
  STATE.activeTags = [];
  STATE.typeFilter = null;
  STATE.focusedActiveTagIndex = -1;
  renderSelectedTags();
  renderList();
}

function renderSelectedTags() {
  const el = $("selected-tags");
  if (!el) return;
  
  // Build active items list
  const activeItems = [];
  if (STATE.typeFilter) {
    activeItems.push({ type: "type", value: STATE.typeFilter });
  }
  STATE.activeTags.forEach(t => {
    activeItems.push({ type: "tag", value: t });
  });

  const n = activeItems.length;
  el.style.display = n ? "flex" : "none";
  
  const strategyBtn = STATE.activeTags.length >= 2 ? `
    <div class="strategy-toggle" onclick="toggleTagMatchStrategy()" title="Click to change matching logic">
      Match: <span class="val">${STATE.tagMatchStrategy.toUpperCase()}</span>
    </div>
  ` : "";
  
  let html = "";
  activeItems.forEach((item, idx) => {
    const isFocused = idx === STATE.focusedActiveTagIndex;
    const focusClass = isFocused ? " focused" : "";
    if (item.type === "type") {
      html += `<span class="stag type-pill${focusClass}">⚙️ ${esc(item.value)}<span class="stag-x" onclick="removeActiveType()">\u2715</span></span>`;
    } else {
      html += `<span class="stag${focusClass}">#${esc(item.value)}<span class="stag-x" onclick="removeActiveTag('${esc(item.value)}')">\u2715</span></span>`;
    }
  });

  el.innerHTML = html + 
    (n > 1 ? `<span class="stag-clear" onclick="clearAllTags()">Clear all</span>` : "") + 
    strategyBtn;
}

// ══════════════════════════════════════════════════════════
//  PWA INSTALL PROMPT
// ══════════════════════════════════════════════════════════
let _deferredInstallPrompt = null;

window.addEventListener("beforeinstallprompt", (e) => {
  e.preventDefault();
  _deferredInstallPrompt = e;
  showInstallSection();
});

window.addEventListener("appinstalled", () => {
  _deferredInstallPrompt = null;
  markAsInstalled();
  toast("Vault installed", "success");
});

function showInstallSection() {
  const sec = $("install-section");
  if (sec) sec.classList.add("show");
}

function markAsInstalled() {
  const sec = $("install-section");
  if (sec) sec.classList.add("show");
  const btn = $("install-btn");
  if (btn) {
    btn.textContent = "Installed ✓";
    btn.classList.add("installed");
    btn.onclick = null;
  }
}

async function installPWA() {
  if (!_deferredInstallPrompt) {
    toast("Use your browser's menu to install this app");
    return;
  }
  _deferredInstallPrompt.prompt();
  const result = await _deferredInstallPrompt.userChoice;
  if (result.outcome === "accepted") {
    _deferredInstallPrompt = null;
  }
}

// Check if already running as installed PWA
function checkInstalledState() {
  if (window.matchMedia("(display-mode: standalone)").matches ||
      window.navigator.standalone === true) {
    markAsInstalled();
  }
}

// ══════════════════════════════════════════════════════════
//  THEME
// ══════════════════════════════════════════════════════════
function applyTheme(theme) {
  let isLight = false;
  if (theme === "light") {
    isLight = true;
  } else if (theme === "system") {
    isLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  }
  const metaThemeColor = document.querySelector('meta[name="theme-color"]');
  if (isLight) {
    document.documentElement.classList.add("light-theme");
    if (metaThemeColor) metaThemeColor.setAttribute("content", "#f8fafc");
  } else {
    document.documentElement.classList.remove("light-theme");
    if (metaThemeColor) metaThemeColor.setAttribute("content", "#0a0b10");
  }
}

function setTheme(theme, el) {
  STATE.theme = theme;
  LS.set("vault_theme", theme);
  applyTheme(theme);
  renderThemeUI();
}

function renderThemeUI() {
  const chips = document.querySelectorAll("#theme-row .sort-chip");
  if (!chips.length) return;
  chips.forEach(c => c.classList.remove("on"));
  const active = document.getElementById("theme-" + STATE.theme);
  if (active) active.classList.add("on");
}

// ══════════════════════════════════════════════════════════
//  START
// ══════════════════════════════════════════════════════════
boot();
checkInstalledState();
