const CACHE_NAME = "family-organizer-cache-v1";
const urlsToCache = [
  "/",
  "/index.html",
  "/styles.css",
  "/ssiAuth.js",
  "/images/pawn.png",
  "/images/wallet.jpg"
];

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
  );
});

self.addEventListener("fetch", event => {
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request);
    })
  );
});
