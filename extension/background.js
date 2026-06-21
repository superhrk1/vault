// Map to temporarily store credentials by tab ID
const pendingAutofills = new Map();

// Listen for messages from the Vault PWA
chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  console.log("[Vault Extension] Received external message:", message);
  
  if (message.action === "ping") {
    sendResponse({ success: true, version: "1.0" });
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

// Listen for messages from our content script running in the newly opened tab
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "getPendingCredentials") {
    const tabId = sender.tab?.id;
    if (tabId && pendingAutofills.has(tabId)) {
      const credentials = pendingAutofills.get(tabId);
      // Clean up immediately so they cannot be retrieved again
      pendingAutofills.delete(tabId);
      
      console.log("[Vault Extension] Dispatching credentials to tab:", tabId);
      sendResponse({ hasCredentials: true, ...credentials });
    } else {
      sendResponse({ hasCredentials: false });
    }
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
