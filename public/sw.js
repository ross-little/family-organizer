// Update marker: 2025-09-26 13:48
const CACHE_NAME = "family-organizer-cache-v3"; // bump version each deploy
const urlsToCache = [
  "/",
  "/index.html",
  "/styles.css",
  "/ssiAuth.js",
  "/images/pawn.png",
  "/images/wallet.jpg"
];

// ===== Install =====
self.addEventListener("install", event => {
  console.log("[SW] Installing new version...");
  self.skipWaiting(); // immediately activate new SW
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
  );
});

// ===== Activate =====
self.addEventListener("activate", event => {
  console.log("[SW] Activating new version...");
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.map(key => {
          if (key !== CACHE_NAME) {
            console.log("[SW] Deleting old cache:", key);
            return caches.delete(key);
          }
        })
      )
    )
  );
  self.clients.claim(); // take control of all pages immediately
});

// ===== Fetch =====
self.addEventListener("fetch", event => {
  const { request } = event;

  // Network-first for navigations (HTML)
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request)
        .then(resp => {
          const copy = resp.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(request, copy));
          return resp;
        })
        .catch(() => caches.match(request))
    );
    return;
  }

  // Cache-first for other assets (CSS, JS, images)
  event.respondWith(
    caches.match(request).then(resp => resp || fetch(request))
  );
});

