const CACHE = "vault-pwa-v111";
const SHELL = ["./", "./index.html", "./config.js?v=110", "./app.js?v=110", "./manifest.json", "./oauth_callback.html"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;
  const url = e.request.url;
  // Never intercept Google OAuth / Drive API calls
  if (url.includes("accounts.google.com") || url.includes("googleapis.com") || url.includes("fonts.g")) return;
  // Network first, cache as the offline fallback — a new release applies on the
  // next open instead of one launch later.
  e.respondWith(
    fetch(e.request).then(resp => {
      if (resp && resp.status === 200 && resp.type === "basic") {
        const cloned = resp.clone();
        caches.open(CACHE).then(c => c.put(e.request, cloned));
      }
      return resp;
    }).catch(() => caches.match(e.request).then(hit => hit || caches.match("./index.html")))
  );
});
