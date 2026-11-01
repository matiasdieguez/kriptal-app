const CACHE = 'kriptal-v11';
const APP_ROOT = new URL('./', self.registration.scope).pathname;
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(
  caches.keys().then(names => Promise.all(
    names
      .filter(name => name.startsWith('kriptal-v') && name !== CACHE)
      .map(name => caches.delete(name))
  )).then(() => self.clients.claim())
));
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    let response;
    try {
      response = await fetch(event.request);
    } catch (error) {
      const cached = await cache.match(event.request);
      if (cached) return cached;
      if (event.request.mode === 'navigate') {
        const app = await cache.match(APP_ROOT);
        if (app) return app;
      }
      throw error;
    }
    if (response.ok && new URL(event.request.url).origin === self.location.origin) {
      try {
        await cache.put(event.request, response.clone());
      } catch (error) {
        console.warn('Kriptal could not cache a response for offline use', error);
      }
    }
    return response;
  })());
});
