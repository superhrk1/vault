# 🔐 Vault — Encrypted Personal Data Manager

A Progressive Web App (PWA) that installs on Android as a native-like app.
Manages passwords, subscriptions, bookmarks and notes — all AES-256 encrypted,
synced to your own Google Drive.

## Features
- 🔑 Passwords · 💳 Subscriptions · 🔖 Bookmarks · 📝 Notes
- **Dual-Password Security**: Fast 4-digit PIN for local unlock, Strong Cloud Master Password for Google Drive backups
- AES-256-GCM encryption with high-performance Key Encryption Key (KEK) caching
- Google Drive sync — utilizes the hidden `appDataFolder` to prevent accidental deletion
- Copy username/password to clipboard without showing the value
- Multi-tag system for grouping, filtering and sorting
- Password strength meter + built-in password generator
- Import / Export (encrypted JSON + CSV)
- Fully offline — Service Worker caches the modular ES app
- Installs to Android home screen via Chrome

## Setup
→ See **[SETUP.md](SETUP.md)** for complete step-by-step instructions.

**TL;DR:**
1. Push this repo to GitHub → enable GitHub Pages (Actions source)
2. Create Google OAuth Client ID → paste into `config.js` → push again
3. Open `https://YOUR_USERNAME.github.io/vault/` in Android Chrome → install

## Configuration
Only one file to edit: **`config.js`**
```js
GOOGLE_CLIENT_ID: "YOUR_CLIENT_ID.apps.googleusercontent.com",
```

## Privacy
- No server. No account. No telemetry.
- Your vault lives in your browser's localStorage (encrypted) + your own Google Drive (encrypted).
- Only you can decrypt it — Google cannot.
