/**
 * Service Worker - Deploy Template PWA
 * Version: 1.0.0
 * =============================================================================
 * Basic service worker for PWA installation support.
 * Provides shell caching for offline access to static assets.
 * 
 * M12: Added to enable full PWA functionality.
 * =============================================================================
 */

const CACHE_NAME = 'deploy-template-v1';
const STATIC_ASSETS = [
    '/',
    '/static/css/main.css',
    '/static/css/tailwind.css',
    '/static/css/fonts.css',
    '/static/js/main.js',
    '/static/favicon.svg',
    '/static/manifest.json',
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                console.log('[SW] Caching static assets');
                return cache.addAll(STATIC_ASSETS);
            })
            .then(() => {
                console.log('[SW] Installation complete');
                return self.skipWaiting();
            })
            .catch((error) => {
                console.error('[SW] Installation failed:', error);
            })
    );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys()
            .then((cacheNames) => {
                return Promise.all(
                    cacheNames
                        .filter((name) => name !== CACHE_NAME)
                        .map((name) => {
                            console.log('[SW] Deleting old cache:', name);
                            return caches.delete(name);
                        })
                );
            })
            .then(() => {
                console.log('[SW] Activation complete');
                return self.clients.claim();
            })
    );
});

// Fetch event - serve from cache, fallback to network
self.addEventListener('fetch', (event) => {
    // Only handle GET requests
    if (event.request.method !== 'GET') {
        return;
    }

    // Skip non-http(s) requests
    if (!event.request.url.startsWith('http')) {
        return;
    }

    event.respondWith(
        caches.match(event.request)
            .then((cachedResponse) => {
                if (cachedResponse) {
                    // Return cached version
                    return cachedResponse;
                }

                // Not in cache, fetch from network
                return fetch(event.request)
                    .then((response) => {
                        // Don't cache non-ok responses
                        if (!response || response.status !== 200) {
                            return response;
                        }

                        // Clone the response since it can only be consumed once
                        const responseToCache = response.clone();

                        // Only cache static assets
                        if (event.request.url.includes('/static/')) {
                            caches.open(CACHE_NAME)
                                .then((cache) => {
                                    cache.put(event.request, responseToCache);
                                });
                        }

                        return response;
                    })
                    .catch(() => {
                        // Network failed, return offline fallback if available
                        return caches.match('/');
                    });
            })
    );
});
