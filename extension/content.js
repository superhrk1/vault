// Immediately ask the background script if there are pending credentials for this tab
chrome.runtime.sendMessage({ action: "getPendingCredentials" }, (response) => {
  if (chrome.runtime.lastError) {
    console.log("[Vault Extension] Error checking pending credentials:", chrome.runtime.lastError.message);
    return;
  }

  if (response && response.hasCredentials) {
    console.log("[Vault Extension] Found credentials for this page. Attempting to autofill...");
    
    // Wait a brief moment or try immediately, and also retry if fields aren't rendered yet
    autofillCredentials(response.username, response.password);
  }
});

function autofillCredentials(username, password) {
  let attempts = 0;
  const maxAttempts = 5;
  const interval = 500; // ms

  const timer = setInterval(() => {
    attempts++;
    const success = doFill(username, password);
    
    if (success || attempts >= maxAttempts) {
      clearInterval(timer);
      if (success) {
        console.log("[Vault Extension] Autofill succeeded.");
      } else {
        console.log("[Vault Extension] Autofill failed to find suitable input fields.");
      }
    }
  }, interval);
}

function doFill(username, password) {
  // Find password inputs
  const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'));
  if (passwordInputs.length === 0) {
    return false;
  }

  // Choose the first password input
  const passwordInput = passwordInputs[0];

  // Try to find the corresponding username input
  // Typically, the username input is the text/email input immediately before the password input
  let usernameInput = null;

  // 1. Look for text/email inputs in the same form or close to the password input
  const allInputs = Array.from(document.querySelectorAll('input'));
  const pwIdx = allInputs.indexOf(passwordInput);
  
  if (pwIdx > 0) {
    // Look backwards from password input for the first text/email/username input
    for (let i = pwIdx - 1; i >= 0; i--) {
      const inp = allInputs[i];
      const type = inp.type.toLowerCase();
      
      // Match common username field types and names
      if (type === "text" || type === "email" || type === "number" || inp.name?.toLowerCase().includes("user") || inp.id?.toLowerCase().includes("user")) {
        // Ensure it's visible and not hidden
        if (inp.offsetWidth > 0 || inp.offsetHeight > 0) {
          usernameInput = inp;
          break;
        }
      }
    }
  }

  // 2. Fallback: search by name/id attributes globally if not found by proximity
  if (!usernameInput) {
    usernameInput = document.querySelector('input[type="email"], input[name*="user" i], input[name*="login" i], input[id*="user" i], input[id*="login" i]');
  }

  // Fill password
  fillField(passwordInput, password);

  // Fill username if found
  if (usernameInput) {
    fillField(usernameInput, username);
  }

  // Focus the password input to guide the user
  passwordInput.focus();

  return true;
}

function fillField(input, value) {
  if (!input || !value) return;
  
  input.value = value;
  
  // Dispatch events to notify reactive frameworks (React, Angular, Vue, etc.)
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
  
  // Highlight the field briefly so the user sees it was filled by the extension
  const originalBg = input.style.backgroundColor;
  input.style.backgroundColor = "rgba(124, 106, 245, 0.15)"; // Light Purple highlight
  setTimeout(() => {
    input.style.backgroundColor = originalBg;
  }, 1000);
}
