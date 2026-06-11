const ITERS = 310000;
const enc = s => new TextEncoder().encode(s);
const dec = b => new TextDecoder().decode(b);
const rnd = n => crypto.getRandomValues(new Uint8Array(n));
const b64e = u => btoa(String.fromCharCode(...u));
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

export class VaultCrypto {
  constructor() {
    this.masterKeyObj = null; // The cached raw AES-GCM CryptoKey for the session
  }

  // --- PRIMITIVES ---
  async deriveKEK(password, salt) {
    const mat = await crypto.subtle.importKey("raw", enc(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: ITERS, hash: "SHA-256" },
      mat, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
  }

  async hashPassword(password) {
    const buf = await crypto.subtle.digest("SHA-256", enc(password + "__vault_kdf_2024__"));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  async verifyPassword(password, hash) {
    const h = await this.hashPassword(password);
    return h === hash;
  }

  // --- MASTER KEY GENERATION ---
  async generateMasterKey() {
    return await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  }

  // --- WRAPPING / UNWRAPPING DEK ---
  async wrapMasterKey(masterKey, kek) {
    const iv = rnd(12);
    const wrapped = await crypto.subtle.wrapKey("raw", masterKey, kek, { name: "AES-GCM", iv });
    const buf = new Uint8Array(12 + wrapped.byteLength);
    buf.set(iv, 0); buf.set(new Uint8Array(wrapped), 12);
    return b64e(buf);
  }

  async unwrapMasterKey(wrappedB64, kek) {
    const buf = b64d(wrappedB64);
    const iv = buf.slice(0, 12);
    const ct = buf.slice(12);
    return await crypto.subtle.unwrapKey(
      "raw", ct, kek, { name: "AES-GCM", iv },
      { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
  }

  // --- DATA ENCRYPTION (V2 - FAST) ---
  async encryptData(data) {
    if (!this.masterKeyObj) throw new Error("Vault locked");
    const iv = rnd(12);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, this.masterKeyObj, enc(JSON.stringify(data)));
    const buf = new Uint8Array(12 + ct.byteLength);
    buf.set(iv, 0); buf.set(new Uint8Array(ct), 12);
    return b64e(buf);
  }

  async decryptData(b64) {
    if (!this.masterKeyObj) throw new Error("Vault locked");
    const buf = b64d(b64);
    const iv = buf.slice(0, 12);
    const ct = buf.slice(12);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, this.masterKeyObj, ct);
    return JSON.parse(dec(pt));
  }

  // --- LEGACY SUPPORT (V1 - SLOW) ---
  async decryptLegacy(b64, pin) {
    const buf = b64d(b64);
    const salt = buf.slice(0, 16);
    const iv = buf.slice(16, 28);
    const ct = buf.slice(28);
    const kek = await this.deriveKEK(pin, salt);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, kek, ct);
    return JSON.parse(dec(pt));
  }

  // --- LOCAL PIN LIFECYCLE ---
  async setupLocalPin(pin, masterKey) {
    const salt = rnd(16);
    const kek = await this.deriveKEK(pin, salt);
    const wrapped = await this.wrapMasterKey(masterKey, kek);
    const hash = await this.hashPassword(pin);
    localStorage.setItem("vault_hash", hash);
    localStorage.setItem("vault_pin_salt", b64e(salt));
    localStorage.setItem("vault_wrapped_master", wrapped);
  }

  async unlockLocalPin(pin) {
    const hash = await this.hashPassword(pin);
    if (hash !== localStorage.getItem("vault_hash")) return false;
    
    const salt = b64d(localStorage.getItem("vault_pin_salt"));
    const wrapped = localStorage.getItem("vault_wrapped_master");
    const kek = await this.deriveKEK(pin, salt);
    
    try {
      this.masterKeyObj = await this.unwrapMasterKey(wrapped, kek);
      return true;
    } catch(e) {
      return false; // Decryption failed
    }
  }

  // --- CLOUD MASTER PASSWORD LIFECYCLE ---
  async setupCloudPassword(password, masterKey) {
    const salt = rnd(16);
    const kek = await this.deriveKEK(password, salt);
    const wrapped = await this.wrapMasterKey(masterKey, kek);
    const hash = await this.hashPassword(password);
    localStorage.setItem("vault_cloud_hash", hash);
    localStorage.setItem("vault_cloud_salt", b64e(salt));
    localStorage.setItem("vault_cloud_wrapped", wrapped);
    return { cloud_salt: b64e(salt), cloud_wrapped: wrapped, cloud_hash: hash };
  }

  async unlockCloudPassword(password, saltB64, wrappedB64) {
    const salt = b64d(saltB64);
    const kek = await this.deriveKEK(password, salt);
    try {
      this.masterKeyObj = await this.unwrapMasterKey(wrappedB64, kek);
      return true;
    } catch(e) {
      return false;
    }
  }
}

export const VaultCryptoManager = new VaultCrypto();
