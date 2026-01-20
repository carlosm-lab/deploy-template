/**
 * Service Worker Registration
 * Moved to external file for CSP compliance (script-src 'self')
 */
(function () {
    'use strict';

    if ('serviceWorker' in navigator) {
        window.addEventListener('load', function () {
            navigator.serviceWorker.register('/static/sw.js')
                .then(function (registration) {
                    console.log('[SW] Registered:', registration.scope);
                })
                .catch(function (error) {
                    console.warn('[SW] Registration failed:', error);
                });
        });
    }
})();
