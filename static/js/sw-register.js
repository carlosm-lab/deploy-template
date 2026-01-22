/**
 * Service Worker Registration
 * Moved to external file for CSP compliance (script-src 'self')
 * A2 Fix: Conditional logging disabled in production
 */
(function () {
    'use strict';

    // A2 Fix: Only log in development (localhost)
    var isDevMode = window.location.hostname === 'localhost' ||
        window.location.hostname === '127.0.0.1';

    if ('serviceWorker' in navigator) {
        window.addEventListener('load', function () {
            navigator.serviceWorker.register('/static/sw.js')
                .then(function (registration) {
                    if (isDevMode) {
                        console.log('[SW] Registered:', registration.scope);
                    }
                })
                .catch(function (error) {
                    if (isDevMode) {
                        console.warn('[SW] Registration failed:', error);
                    }
                });
        });
    }
})();
