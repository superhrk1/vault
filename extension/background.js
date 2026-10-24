// Map to temporarily store credentials by tab ID (explicitly opened from PWA)
const pendingAutofills = new Map();

// Volatile in-memory store for synced credentials (cleared when browser restarts or PWA locks)
let syncedItems = [];

// Only the Vault app itself may send messages (also enforced by externally_connectable)
const ALLOWED_ORIGINS = ["https://superhrk1.github.io", "http://localhost", "http://127.0.0.1"];

function isAllowedSender(sender) {
  let origin = sender?.origin || "";
  if (!origin && sender?.url) {
    try { origin = new URL(sender.url).origin; } catch (e) { origin = ""; }
  }
  return ALLOWED_ORIGINS.some(o => origin === o || origin.startsWith(o + ":"));
}

function parseUrl(u) {
  try {
    const s = String(u || "").trim();
    const url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(s) ? s : "https://" + s);
    return (url.protocol === "https:" || url.protocol === "http:") ? url : null;
  } catch (e) {
    return null;
  }
}

// A saved login may fill on its own host or a subdomain of it — never on a
// sibling host (a.github.io must not fill on b.github.io), and never on a
// plain-http page unless the login itself was saved for http.
function hostMatches(savedUrl, pageUrl) {
  const saved = parseUrl(savedUrl);
  const page = parseUrl(pageUrl);
  if (!saved || !page) return false;
  if (page.protocol !== "https:" && saved.protocol !== "http:") return false;
  const strip = h => h.toLowerCase().replace(/^www\./, "");
  const s = strip(saved.hostname);
  const p = strip(page.hostname);
  return p === s || p.endsWith("." + s);
}

// Listen for messages from the Vault PWA (never log these — they carry passwords)
chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  if (!isAllowedSender(sender)) {
    sendResponse({ success: false, error: "Sender not allowed" });
    return true;
  }

  if (message.action === "ping") {
    sendResponse({ success: true, version: "1.2" });
    return true;
  }

  if (message.action === "syncVault") {
    syncedItems = Array.isArray(message.items) ? message.items : [];
    sendResponse({ success: true });
    return true;
  }

  if (message.action === "clearVault") {
    syncedItems = [];
    pendingAutofills.clear();
    sendResponse({ success: true });
    return true;
  }

  if (message.action === "openAndAutofill") {
    const { username, password } = message;
    const target = parseUrl(message.url);
    if (!target) {
      sendResponse({ success: false, error: "Missing or unsupported URL" });
      return true;
    }

    chrome.tabs.create({ url: target.href }, (tab) => {
      if (tab && tab.id) {
        // Released only to a page on the requested site — not after a redirect elsewhere
        pendingAutofills.set(tab.id, { username, password, url: target.href });
        sendResponse({ success: true, tabId: tab.id });
      } else {
        sendResponse({ success: false, error: "Failed to create tab" });
      }
    });
    return true; // Keep message channel open for async response
  }
});

// Listen for messages from our content script running in web pages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "getCredentials") {
    const tabId = sender.tab?.id;
    // Trust the URL Chrome reports for the tab, never one supplied by the page
    const pageUrl = sender.url || sender.tab?.url || "";

    // Top frame only — a hidden third-party iframe must never receive credentials
    if (sender.frameId !== 0 || !pageUrl) {
      sendResponse({ hasCredentials: false });
      return true;
    }

    // 1. Tabs explicitly opened from the PWA
    if (tabId && pendingAutofills.has(tabId)) {
      const pending = pendingAutofills.get(tabId);
      if (hostMatches(pending.url, pageUrl)) {
        pendingAutofills.delete(tabId); // single use
        sendResponse({ hasCredentials: true, username: pending.username, password: pending.password });
        return true;
      }
    }

    // 2. Saved logins for this exact site (or its subdomains)
    const matched = syncedItems.find(item => item && item.url && hostMatches(item.url, pageUrl));
    if (matched) {
      sendResponse({ hasCredentials: true, username: matched.username, password: matched.password });
      return true;
    }

    sendResponse({ hasCredentials: false });
    return true;
  }
});

// Clean up credentials if a tab is closed before it retrieves them
chrome.tabs.onRemoved.addListener((tabId) => {
  pendingAutofills.delete(tabId);
});
