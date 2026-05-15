// ╔══════════════════════════════════════════════════════════════╗
// ║           VAULT — YOUR ONLY CONFIGURATION FILE              ║
// ║                                                              ║
// ║  STEP 1: Follow SETUP.md to get your Google Client ID       ║
// ║  STEP 2: Paste it below (replace the placeholder)           ║
// ║  STEP 3: Save, commit, push — done.                         ║
// ╚══════════════════════════════════════════════════════════════╝

const VAULT_CONFIG = {

  // ▼ PASTE YOUR GOOGLE CLIENT ID HERE (the only thing you need to change)
  GOOGLE_CLIENT_ID: "PASTE_YOUR_CLIENT_ID_HERE.apps.googleusercontent.com",

  // ── Advanced settings (leave as-is unless you know what you're doing) ──
  DRIVE_FILE_NAME:  "vault-encrypted-backup.json",   // filename stored in your Drive
  DRIVE_SCOPE:      "https://www.googleapis.com/auth/drive.file",
  PBKDF2_ITERATIONS: 310000,                          // key derivation strength
  APP_NAME:         "Vault",
};
