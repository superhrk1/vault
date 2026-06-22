// Map to temporarily store credentials by tab ID (explicitly opened from PWA)
const pendingAutofills = new Map();

// Volatile in-memory store for synced credentials (cleared when browser restarts or PWA locks)
let syncedItems = [];

// Helper to extract the main domain/host from any URL string, ignoring subdomains/www
// and correctly handling country-code second-level domains (ccSLDs like co.uk)
function extractDomain(url) {
  if (!url) return "";
  let hostname = url.trim().toLowerCase();
  
  if (hostname.includes("://")) {
    try {
      hostname = new URL(hostname).hostname;
    } catch (e) {
      hostname = hostname.split("://")[1];
    }
  }
  
  hostname = hostname.split("/")[0].split(":")[0];
  
  if (hostname.startsWith("www.")) {
    hostname = hostname.slice(4);
  }
  
  // Handle IPv4 addresses
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    return hostname;
  }
  
  const parts = hostname.split(".");
  if (parts.length <= 2) {
    return hostname;
  }
  
  const lastPart = parts[parts.length - 1];
  const secondLastPart = parts[parts.length - 2];
  
  const commonSLDs = new Set(["co", "com", "org", "net", "gov", "edu", "ac", "or", "ne"]);
  const isccSLD = lastPart.length === 2 && (secondLastPart.length <= 3 && commonSLDs.has(secondLastPart));
  
  if (isccSLD) {
    return parts.slice(-3).join(".");
  } else {
    return parts.slice(-2).join(".");
  }
}

// Listen for messages from the Vault PWA
chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  console.log("[Vault Extension] Received external message:", message);
  
  if (message.action === "ping") {
    sendResponse({ success: true, version: "1.1" });
    return true;
  }

  if (message.action === "syncVault") {
    syncedItems = message.items || [];
    console.log("[Vault Extension] Synced", syncedItems.length, "credentials.");
    sendResponse({ success: true });
    return true;
  }

  if (message.action === "clearVault") {
    syncedItems = [];
    console.log("[Vault Extension] Cleared synced credentials.");
    sendResponse({ success: true });
    return true;
  }

  if (message.action === "openAndAutofill") {
    const { url, username, password } = message;
    if (!url) {
      sendResponse({ success: false, error: "Missing URL" });
      return true;
    }

    // Open a new tab
    chrome.tabs.create({ url: url }, (tab) => {
      if (tab && tab.id) {
        // Store credentials associated with this new tab ID
        pendingAutofills.set(tab.id, { username, password });
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
    
    // 1. Check pendingAutofills first (tabs explicitly launched from PWA)
    if (tabId && pendingAutofills.has(tabId)) {
      const credentials = pendingAutofills.get(tabId);
      // Clean up immediately so they cannot be retrieved again
      pendingAutofills.delete(tabId);
      
      console.log("[Vault Extension] Dispatching pending credentials to tab:", tabId);
      sendResponse({ hasCredentials: true, ...credentials });
      return true;
    }
    
    // 2. Match current page's domain against in-memory synced credentials
    const tabUrl = sender.tab?.url || message.url || "";
    if (tabUrl) {
      const tabDomain = extractDomain(tabUrl);
      if (tabDomain) {
        const matched = syncedItems.find(item => {
          if (!item.url) return false;
          const itemDomain = extractDomain(item.url);
          return itemDomain === tabDomain;
        });
        
        if (matched) {
          console.log("[Vault Extension] Domain match found for tab:", tabId, "Domain:", tabDomain);
          sendResponse({
            hasCredentials: true,
            username: matched.username,
            password: matched.password
          });
          return true;
        }
      }
    }

    sendResponse({ hasCredentials: false });
    return true;
  }
});

// Clean up credentials if a tab is closed before it retrieves them
chrome.tabs.onRemoved.addListener((tabId) => {
  if (pendingAutofills.has(tabId)) {
    pendingAutofills.delete(tabId);
    console.log("[Vault Extension] Cleaned up unused credentials for closed tab:", tabId);
  }
});
