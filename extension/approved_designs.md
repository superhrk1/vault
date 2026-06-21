# Automatic Credential Matching & Autofill by Domain

This plan introduces automatic matching and autofilling of credentials. When a user logs into their Vault PWA, their credentials are securely synced to the extension's in-memory (RAM) storage. As the user browses the web, the extension automatically detects the domain (e.g., `xyz.com`), queries its in-memory storage, and autofills the matching credentials.

## User Review Required

> [!IMPORTANT]
> **Security Aspect:** Synced credentials are kept strictly in the extension background service worker's memory (volatile RAM). They are never written to disk/local storage inside the extension, ensuring they vanish when the browser is closed or when the user locks the PWA.

## Proposed Changes

### Vault Web App

#### [MODIFY] [app.js](file:///d:/AI_Projs/1_vault/vault/app.js)
- Add a `syncWithExtension(clear)` helper to send decrypted password credentials to the browser extension or clear them.
- Call `syncWithExtension(false)` after items are decrypted in `loadItems()`.
- Call `syncWithExtension(false)` after items are successfully saved in `persistItems()`.
- Call `syncWithExtension(false)` after the user updates the Autofill Extension ID in `saveExtensionId()`.
- Call `syncWithExtension(true)` in `lockVault()` to clear extension cache when the vault is locked.

---

### Vault Browser Extension

#### [MODIFY] [background.js](file:///d:/AI_Projs/1_vault/vault/extension/background.js)
- Maintain an in-memory `syncedItems` array (cleared on start).
- Implement a helper `extractDomain(url)` that extracts the main domain/host from any URL string, ignoring subdomains/www and handling country-code second-level domains (e.g., `google.co.uk` -> `google.co.uk`, `sub.github.com` -> `github.com`).
- Add message listeners for:
  - `"syncVault"`: updates the in-memory `syncedItems` list.
  - `"clearVault"`: clears the `syncedItems` list.
  - `"getCredentials"`: replaces `getPendingCredentials`. It first checks `pendingAutofills` (for tabs opened explicitly from PWA). If empty, it uses `extractDomain` to match the current tab's domain against the `syncedItems` URLs and returns the first match if found.

#### [MODIFY] [content.js](file:///d:/AI_Projs/1_vault/vault/extension/content.js)
- Replace the `getPendingCredentials` message call with a `getCredentials` message passing the current page's hostname (`window.location.hostname`).
- Autofills fields if the response returns credentials.

## Verification Plan

### Manual Verification
1. Load the updated extension in Developer Mode.
2. Link the extension ID to the Vault PWA via PWA Settings.
3. Log into the Vault PWA (unlocking it).
4. Add a password item with URL `https://example.com/test-login` and test credentials.
5. In a new tab, navigate directly to `http://example.com` (or any sub-page).
6. Verify that the extension automatically finds the input fields and fills the username and password with a brief purple highlight.
7. Lock the Vault PWA, refresh the `example.com` tab, and verify that credentials are no longer autofilled (since the memory was cleared on lock).
