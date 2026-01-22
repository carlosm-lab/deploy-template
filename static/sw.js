/**
 * Service Worker - Deploy Template PWA
 * Version: 1.5.0
 * =============================================================================
 * Service worker for PWA installation support.
 * Uses Cache-First for static assets, Network-First for dynamic content.
 * 
 * SECURITY: Does NOT cache dynamic routes (/) to prevent stale content issues.
 * 
 * VERSIONING: Cache invalidation uses version + timestamp.
 * =============================================================================
 */

/**
 * CACHE VERSIONING STRATEGY (A3: Enhanced Documentation):
 * 
 * The cache name combines:
 * 1. CACHE_VERSION: Increment for breaking changes (CSS/JS structure changes)
 * 2. DEPLOY_HASH: Updated automatically on each Vercel deploy
 * 
 * HOW TO UPDATE:
 * ==============
 * 
 * AUTOMATIC (GitHub Actions - RECOMMENDED):
 * - The CI/CD pipeline automatically updates DEPLOY_HASH on every push
 * - See .github/workflows/ci.yml for the sed command
 * 
 * MANUAL DEPLOYS (Vercel Dashboard/CLI):
 * - If deploying directly via Vercel without CI:
 *   1. Update DEPLOY_HASH below with current date: YYYYMMDDHHMM
 *   2. Or increment CACHE_VERSION for major changes
 * 
 * VERIFYING CACHE UPDATE:
 * - Open browser DevTools > Application > Service Workers
 * - Check the "Status" shows the new version
 * - Users will get updated cache on next visit
 * 
 * ==============
 * 
 * NOTE: If you're seeing stale content, increment CACHE_VERSION.
 */

// Cache versioning - DEPLOY_HASH should be updated on each deploy
// Format: YYYYMMDDHHMM for timestamp-based, or first 8 chars of commit SHA
const CACHE_VERSION = 14;  // Security audit update 2026-01-21 (Cycle 1)
const DEPLOY_HASH = '202601220700';  // AUTO-UPDATE: CI should replace this
const CACHE_NAME = `deploy-template-v${CACHE_VERSION}-${DEPLOY_HASH}`;

// B1: Debug logging flag - set to false for production silence
const DEBUG_SW = false;  // Set to true only when debugging SW issues

function log(message, ...args) {
    if (DEBUG_SW) {
        console.log('[SW]', message, ...args);
    }
}

// Only cache truly static assets - NOT dynamic routes like '/'
// H1-M01: Added lottie, robot, and PWA icons for better offline experience
const STATIC_ASSETS = [
    '/static/css/main.css',
    '/static/css/tailwind.css',
    '/static/css/fonts.css',
    '/static/css/offline.css',
    '/static/js/main.js',
    '/static/js/sw-register.js',
    '/static/js/offline.js',
    '/static/js/error-handlers.js',
    '/static/js/lottie.min.js',
    '/static/js/robot.js',
    '/static/js/robot-animation.json',
    '/static/favicon.svg',
    '/static/manifest.json',
    '/static/offline.html',
    '/static/icons/icon-192.png',
    '/static/icons/icon-512.png',
];

// Install event - cache static assets only
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                log('Caching static assets');
                return cache.addAll(STATIC_ASSETS);
            })
            .then(() => {
                log('Installation complete');
                return self.skipWaiting();
            })
            .catch((error) => {
                log('Installation failed:', error);
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
                            log('Deleting old cache:', name);
                            return caches.delete(name);
                        })
                );
            })
            .then(() => {
                log('Activation complete');
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
                        // M1: Only cache valid same-origin responses
                        // - status 200: successful response
                        // - type 'basic': same-origin (not opaque/cors/error)
                        if (!response || response.status !== 200 || response.type !== 'basic') {
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

