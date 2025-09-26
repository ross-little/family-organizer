// Update marker: 2025-09-26 13:48
const CACHE_NAME = "family-organizer-cache-v2"; // bump version each deploy
const urlsToCache = [
  "/",
  "/index.html",
  "/styles.css",
  "/ssiAuth.js",
  "/images/pawn.png",
  "/images/wallet.jpg"
];

self.addEventListener("install", event => {
  console.log("[SW] Installing new version...");
  self.skipWaiting(); // immediately activate new SW
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
  );
});

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

self.addEventListener("fetch", event => {
  event.respondWith(
    caches.match(event.request).then(response => response || fetch(event.request))
  );
});

