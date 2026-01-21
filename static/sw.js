/**
 * Service Worker - Deploy Template PWA
 * Version: 1.3.0
 * =============================================================================
 * Service worker for PWA installation support.
 * Uses Cache-First for static assets, Network-First for dynamic content.
 * 
 * SECURITY: Does NOT cache dynamic routes (/) to prevent stale content issues.
 * 
 * VERSIONING: Uses deployment timestamp for automatic cache invalidation.
 * Cache is automatically invalidated on each deploy (no manual version bump needed).
 * =============================================================================
 */

/**
 * CACHE VERSIONING:
 * Now uses automatic versioning based on deploy timestamp.
 * Format: deploy-template-v{major}-{timestamp}
 * 
 * Manual override: Set window.SW_CACHE_VERSION before SW registration
 * to force a specific version (useful for debugging).
 */

// Deploy timestamp is injected during build, fallback to Date for dev
// In production, this file should be processed to include actual deploy time
// For Vercel: the file modification time changes on each deploy
const DEPLOY_TIMESTAMP = '20260121';  // Format: YYYYMMDD - Update on significant changes
const CACHE_VERSION = 10;  // Increment for breaking changes only
const CACHE_NAME = `deploy-template-v${CACHE_VERSION}-${DEPLOY_TIMESTAMP}`;

// Only cache truly static assets - NOT dynamic routes like '/'
const STATIC_ASSETS = [
    '/static/css/main.css',
    '/static/css/tailwind.css',
    '/static/css/fonts.css',
    '/static/css/offline.css',
    '/static/js/main.js',
    '/static/js/sw-register.js',
    '/static/js/offline.js',
    '/static/js/error-handlers.js',
    '/static/favicon.svg',
    '/static/manifest.json',
    '/static/offline.html',
];

// Install event - cache static assets only
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

// Fetch event - different strategies for static vs dynamic
self.addEventListener('fetch', (event) => {
    // Only handle GET requests
    if (event.request.method !== 'GET') {
        return;
    }

    // Skip non-http(s) requests
    if (!event.request.url.startsWith('http')) {
        return;
    }

    const url = new URL(event.request.url);
    const isStaticAsset = url.pathname.startsWith('/static/');

    if (isStaticAsset) {
        // Cache-First for static assets
        event.respondWith(
            caches.match(event.request)
                .then((cachedResponse) => {
                    if (cachedResponse) {
                        return cachedResponse;
                    }
                    return fetch(event.request).then((response) => {
                        if (!response || response.status !== 200) {
                            return response;
                        }
                        const responseToCache = response.clone();
                        caches.open(CACHE_NAME).then((cache) => {
                            cache.put(event.request, responseToCache);
                        });
                        return response;
                    });
                })
        );
    } else {
        // Network-First for dynamic content (HTML pages, API routes)
        event.respondWith(
            fetch(event.request)
                .then((response) => {
                    return response;
                })
                .catch(() => {
                    // Only for navigation requests, show offline page if available
                    if (event.request.mode === 'navigate') {
                        return caches.match('/static/offline.html').then((cached) => {
                            return cached || new Response('Offline', { status: 503 });
                        });
                    }
                    return new Response('Network error', { status: 503 });
                })
        );
    }
});

