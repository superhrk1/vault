# Vault — Complete Setup Guide
## From zero to installed Android app in ~15 minutes

---

## What you'll do
1. Push the files to GitHub → auto-deploys to a free HTTPS URL
2. Get a Google Client ID → paste it in `config.js`
3. Push again → Drive sync works
4. Install to Android home screen as an app

---

## PART 1 — Push to GitHub (5 minutes)

### 1. Create a new GitHub repository
- Go to https://github.com/new
- Repository name: `vault` (or anything you like)
- Set to **Private** (recommended — your code stays private)
- ✅ Do NOT initialize with README
- Click **Create repository**

### 2. Enable GitHub Pages with Actions
- In your new repo, go to **Settings → Pages**
- Under "Source" select: **GitHub Actions**
- Click Save

### 3. Upload the files
You can do this two ways:

**Option A — GitHub web upload (easiest, no Git required):**
1. On your repo page, click **"uploading an existing file"** or drag files
2. Upload ALL files maintaining this structure:
   ```
   vault/
   ├── index.html
   ├── config.js          ← you'll edit this
   ├── app.js
   ├── sw.js
   ├── manifest.json
   ├── .github/
   │   └── workflows/
   │       └── deploy.yml
   └── icons/
       ├── icon-192.png   ← see note below
       └── icon-512.png   ← see note below
   ```
3. Commit message: `Initial vault deploy`
4. Click **Commit changes**

**Option B — Git command line:**
```bash
git init
git add .
git commit -m "Initial vault deploy"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/vault.git
git push -u origin main
```

### 4. Wait ~2 minutes for deployment
- Go to **Actions** tab in your repo
- You'll see a workflow running — wait for the green ✓
- Your app is now live at:
  **`https://YOUR_USERNAME.github.io/vault/`**

> 💡 **Icons note:** The app works without icons, but to get a proper home screen icon,
> create two PNG images (192×192 and 512×512 pixels) with a padlock on dark background.
> Free tool: https://favicon.io/favicon-generator/ — use emoji 🔐 and dark background.
> Save as `icons/icon-192.png` and `icons/icon-512.png` and upload to the `icons/` folder.

---

## PART 2 — Google Drive Setup (10 minutes)

### Step 1 — Create a Google Cloud Project
1. Go to https://console.cloud.google.com
2. Click the project dropdown at the top → **"New Project"**
3. Name it `Vault App` → click **Create**
4. Make sure the new project is selected in the dropdown

### Step 2 — Enable the Google Drive API
1. In the left menu: **APIs & Services → Library**
2. Search for **"Google Drive API"**
3. Click it → click **Enable**

### Step 3 — Configure OAuth Consent Screen
1. Left menu: **APIs & Services → OAuth consent screen**
2. User Type: **External** → click **Create**
3. Fill in:
   - App name: `Vault`
   - User support email: your email
   - Developer contact: your email
4. Click **Save and Continue**
5. On Scopes page: click **"Add or Remove Scopes"**
6. Search for `drive.file` → check ✅ `https://www.googleapis.com/auth/drive.file`
7. Click **Update** → **Save and Continue**
8. On Test Users page: click **"+ Add Users"** → add your Gmail address
9. Click **Save and Continue** → **Back to Dashboard**

### Step 4 — Create OAuth 2.0 Credentials
1. Left menu: **APIs & Services → Credentials**
2. Click **"+ Create Credentials"** → **"OAuth 2.0 Client ID"**
3. Application type: **Web application**
4. Name: `Vault PWA`
5. Under **"Authorized JavaScript origins"** → click **"+ Add URI"**
   - Add: `https://YOUR_USERNAME.github.io`
   - (replace YOUR_USERNAME with your actual GitHub username)
6. Under **"Authorized redirect URIs"** → click **"+ Add URI"**
   - Add: `https://YOUR_USERNAME.github.io/vault/`
   - (include the trailing slash and `/vault/`)
7. Click **Create**
8. A popup shows your **Client ID** — it looks like:
   `123456789-abcdefgh.apps.googleusercontent.com`
9. **Copy it** (click the copy icon)

### Step 5 — Paste Client ID into config.js
1. In your GitHub repo, click on `config.js` to open it
2. Click the ✏️ pencil icon to edit
3. Find this line:
   ```javascript
   GOOGLE_CLIENT_ID: "PASTE_YOUR_CLIENT_ID_HERE.apps.googleusercontent.com",
   ```
4. Replace `PASTE_YOUR_CLIENT_ID_HERE.apps.googleusercontent.com` with your actual Client ID
5. Scroll down → click **"Commit changes"** → **"Commit directly to main"**

### Step 6 — Wait for redeploy (~1 minute)
- Go to **Actions** tab → wait for green ✓
- Reload your app at `https://YOUR_USERNAME.github.io/vault/`

---

## PART 3 — Install on Android (2 minutes)

1. Open **Chrome** on your Android phone
2. Navigate to `https://YOUR_USERNAME.github.io/vault/`
3. **Option A:** Chrome shows an "Add to Home Screen" banner at the bottom → tap **Install**
4. **Option B:** Tap the ⋮ (three dots) menu → tap **"Add to Home screen"** or **"Install app"**
5. Confirm — the app appears on your home screen with its own icon
6. Open it — it runs fullscreen with no browser UI, just like a native app

---

## Using Google Drive Sync

Once Client ID is configured:
1. Open the app → tap **⚙️ Settings**
2. Under **Google Drive Sync** → tap **Connect**
3. A Google sign-in popup appears → select your account → allow access
4. **Cloud Password Setup**: You will be prompted to create a **Strong Cloud Master Password**. This password will encrypt your backups. Your local 4-digit PIN is NOT used for Drive backups to prevent brute-force attacks on your cloud data.
5. You'll see "Drive ✓" badge in the status bar
6. From now on, every time you add/edit/delete an item, it auto-syncs to Drive

**Your vault file on Drive:**
- It is stored in the hidden **Application Data** folder (`spaces=appDataFolder`). This means it will not clutter your Google Drive UI and you cannot accidentally delete it.
- It is always encrypted with the randomly generated Data Encryption Key (DEK), which is wrapped by your **Cloud Master Password**.
- Google cannot read your passwords even if they access the file.

**Pulling to another device:**
1. Install the app on a second device / browser
2. Settings → Connect Drive → same Google account
3. Tap **Pull** to download your cloud backup
4. You will be prompted for your **Cloud Master Password** to decrypt the backup.
5. You will then be prompted to set up a new **4-digit PIN** for fast local unlocks on this specific device.

---

## Troubleshooting

**"Not authorized" error when connecting Drive:**
- Check that your GitHub Pages URL is exactly in Authorized JS Origins
- URLs are case-sensitive and must NOT have a trailing slash in JS Origins
- Must have trailing slash in Redirect URIs
- Changes to Google Cloud Console can take up to 5 minutes

**"Add to Home Screen" not appearing:**
- You must be on HTTPS (GitHub Pages provides this)
- Use Chrome browser specifically
- Visit the page at least twice for Chrome to offer install

**Sync says "Session Expired":**
- Google access tokens expire after 1 hour
- Tap "Connect" again in Settings to re-authenticate
- This is a security feature of Google OAuth

**App not updating after push:**
- Hard-refresh in Chrome: hold reload button → "Hard Reload"
- Or clear site data in Chrome settings → re-open app

---

## Security Summary

| What              | How                                          |
|-------------------|----------------------------------------------|
| Encryption        | AES-256-GCM (industry standard)              |
| Key derivation    | PBKDF2-SHA256, 310,000 iterations (Cached)   |
| Passwords         | Dual System: 4-digit PIN (local) + Strong Cloud Password (Sync) |
| Local storage     | Encrypted blob only — no plain text ever     |
| Drive storage     | Encrypted blob in hidden `appDataFolder`     |
| Drive permissions | `drive.appdata` only — can't see other files |
| Clipboard         | Copy without displaying the value on screen  |
